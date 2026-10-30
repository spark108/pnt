const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const path=require('node:path');

(async()=>{
  const browser=await chromium.launch({headless:true,channel:'chrome',args:['--enable-unsafe-swiftshader']});
  try{
    const context=await browser.newContext({ignoreHTTPSErrors:true,httpCredentials:{username:'admin',password:'web-test-password'},viewport:{width:1500,height:1050}});
    await context.addInitScript(()=>localStorage.setItem('pnt.mapSurface','local'));
    const page=await context.newPage(),errors=[],external=[];
    const url=process.argv[2];if(!url)throw Error('Usage: node tests/WebChecks/browser.cjs <WebChecks --serve URL>');
    page.on('pageerror',e=>errors.push(e.message));
    await page.route('**/*',route=>{
      if(new URL(route.request().url()).origin!==new URL(url).origin){external.push(route.request().url());return route.abort()}
      return route.continue();
    });
    await page.goto(url);
    await page.waitForFunction(()=>typeof viewer!=='undefined'&&viewer&&viewer.entities.values.some(e=>e.polyline),{timeout:30000});
    assert.equal(await page.evaluate(()=>viewer.entities.values.filter(e=>e.polyline).length),2);
    assert.equal(await page.evaluate(()=>viewer.entities.values.filter(e=>e.id.startsWith('node:')).length),3);
    assert.equal(await page.locator('#drawer-toggle').getAttribute('aria-expanded'),'false');
    assert.equal(await page.evaluate(()=>Math.round(document.querySelector('#graph').getBoundingClientRect().height)),1050);
    await page.locator('#drawer-toggle').click();
    await page.selectOption('#to','cccccccccccccccc');
    await page.waitForFunction(()=>document.querySelector('#route-nodes').textContent.includes('Frankfurt'));
    assert.match(await page.locator('#route-nodes').textContent(),/Amsterdam → Frankfurt → London/);
    await page.locator('#selected-properties').click();
    await page.locator('#properties-location').click();
    await page.locator('#location-lat').fill('53.4');await page.locator('#location-lon').fill('6.5');
    await page.locator('#location-save').click();
    await page.waitForFunction(()=>!document.querySelector('#location-dialog').open);
    await page.waitForFunction(()=>state.nodes.find(n=>n.id===state.self).location.latitude===53.4);
    assert.equal(await page.evaluate(()=>state.nodes.find(n=>n.id===state.self).location.latitude),53.4);
    await page.getByRole('button',{name:'NAT node · задать геолокацию'}).click();
    await page.locator('#location-lat').fill('51.2');await page.locator('#location-lon').fill('7.3');
    await page.locator('#location-save').click();
    await page.waitForFunction(()=>viewer.entities.values.filter(e=>e.id.startsWith('node:')).length===4);
    await page.locator('#drawer-toggle').click();
    await page.waitForTimeout(1500);
    await page.screenshot({path:path.resolve('.test-data/globe-desktop.png'),fullPage:true});
    await page.evaluate(()=>{state.links=state.links.map(p=>({...p,updated:now()-31000}));render()});
    assert.equal(await page.evaluate(()=>viewer.entities.values.filter(e=>e.polyline).length),0);
    await page.setViewportSize({width:430,height:950});
    await page.screenshot({path:path.resolve('.test-data/globe-mobile.png'),fullPage:true});
    assert.deepEqual(errors,[]);assert.deepEqual(external,[]);
    await page.locator('#drawer-toggle').click();
    await page.selectOption('#map-surface','nasa');
    await page.waitForFunction(()=>document.querySelector('#surface-status').textContent.includes('NASA недоступен'));
    assert(external.length>0&&external.every(url=>new URL(url).hostname==='gibs.earthdata.nasa.gov'));
    assert.equal(await page.evaluate(()=>satelliteLayer),null);
    const tile=await (await page.request.get(url+'/assets/cesium/Assets/Textures/NaturalEarthII/0/0/0.jpg')).body();
    await page.route('https://gibs.earthdata.nasa.gov/**',route=>route.fulfill({status:200,contentType:'image/jpeg',body:tile,headers:{'Access-Control-Allow-Origin':'*'}}));
    await page.selectOption('#map-surface','local');await page.selectOption('#map-surface','nasa');
    await page.waitForFunction(()=>satelliteLayer!==null&&viewer.scene.globe.tilesLoaded);
    assert.equal(await page.evaluate(()=>satelliteLayer.imageryProvider.maximumLevel),8);
    await page.selectOption('#map-surface','local');
    await page.locator('#drawer-toggle').click();
    await page.evaluate(()=>viewer.camera.setView({destination:Cesium.Cartesian3.fromDegrees(5,52,300000),orientation:{heading:0,pitch:-Math.PI/2,roll:0}}));
    await page.mouse.move(250,475);await page.mouse.wheel(0,-15000);await page.waitForTimeout(1200);
    assert.equal(await page.evaluate(()=>viewer.scene.screenSpaceCameraController.minimumZoomDistance),250000);
    assert(await page.evaluate(()=>viewer.camera.positionCartographic.height>=249900),'Camera crossed minimum height');
    assert.deepEqual(errors,[]);
    console.log('PASS: globe, routes, manual locations, fresh links, offline assets, desktop/mobile layout, NASA tile protocol/fallback and mouse-wheel zoom limit.');
  }finally{await browser.close()}
})().catch(e=>{console.error(e);process.exitCode=1});
