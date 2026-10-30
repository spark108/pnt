const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const path=require('node:path');

(async()=>{
  const browser=await chromium.launch({headless:true,channel:'chrome',args:['--enable-unsafe-swiftshader']});
  try{
    const context=await browser.newContext({ignoreHTTPSErrors:true,httpCredentials:{username:'admin',password:'web-test-password'},viewport:{width:1500,height:1050}});
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
    console.log('PASS: local Cesium WebGL rendering, direct links only, route selection, manual location dialogs, NAT node placement, stale link removal, offline assets, desktop/mobile screenshots.');
  }finally{await browser.close()}
})().catch(e=>{console.error(e);process.exitCode=1});
