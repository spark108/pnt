using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;

namespace Pnt;

record TapOffer(string Epoch, int Port, string ReceiveId, string ReceiveKey);

// Directed, single-use key obtained from the authenticated PNT control channel.
sealed class TapCipher
{
    const int Header = 24, Tag = 16;
    internal const int MaxPayload = 1200;
    readonly byte[] id, key;
    readonly object gate = new();
    long sent;
    ulong highest;
    UInt128 seen;
    internal string Id { get; }
    internal TapCipher() : this(RandomNumberGenerator.GetBytes(16), RandomNumberGenerator.GetBytes(32)) { }
    TapCipher(byte[] id, byte[] key) { this.id = id; this.key = key; Id = Convert.ToHexString(id); }

    internal TapOffer Offer(string epoch, int port) => new(epoch, port, Id, Convert.ToHexString(key));
    internal static TapCipher? From(TapOffer? offer, string epoch)
        => offer?.Epoch == epoch && offer.Port is > 0 and <= 65535 &&
           TapControl.Hex(offer.ReceiveId, 32) && TapControl.Hex(offer.ReceiveKey, 64)
           ? new(Convert.FromHexString(offer.ReceiveId), Convert.FromHexString(offer.ReceiveKey)) : null;

    internal byte[] Seal(ReadOnlySpan<byte> payload)
    {
        if (payload.Length is < 1 or > MaxPayload) throw new ArgumentOutOfRangeException(nameof(payload));
        var sequence = Interlocked.Increment(ref sent);
        if (sequence <= 0) throw new InvalidOperationException("TAP sequence exhausted.");
        var packet = new byte[Header + payload.Length + Tag];
        id.CopyTo(packet, 0);
        BinaryPrimitives.WriteInt64BigEndian(packet.AsSpan(16), sequence);
        Span<byte> nonce = stackalloc byte[12]; nonce.Clear();
        packet.AsSpan(16, 8).CopyTo(nonce[4..]);
        using var cipher = new AesGcm(key, Tag);
        cipher.Encrypt(nonce, payload, packet.AsSpan(Header, payload.Length), packet.AsSpan(Header + payload.Length), packet.AsSpan(0, Header));
        return packet;
    }

    internal static string? Recipient(ReadOnlySpan<byte> packet)
        => packet.Length is > Header + Tag and <= Header + Tag + MaxPayload ? Convert.ToHexString(packet[..16]) : null;

    internal byte[]? Open(ReadOnlySpan<byte> packet)
    {
        if (packet.Length is <= Header + Tag or > Header + Tag + MaxPayload || !packet[..16].SequenceEqual(id)) return null;
        var seq = BinaryPrimitives.ReadUInt64BigEndian(packet[16..]);
        if (seq == 0) return null;
        lock (gate)
        {
            if (seq <= highest && (highest - seq >= 128 || (seen & ((UInt128)1 << (int)(highest - seq))) != 0)) return null;
            var payload = new byte[packet.Length - Header - Tag];
            Span<byte> nonce = stackalloc byte[12]; nonce.Clear();
            packet.Slice(16, 8).CopyTo(nonce[4..]);
            try
            {
                using var cipher = new AesGcm(key, Tag);
                cipher.Decrypt(nonce, packet.Slice(Header, payload.Length), packet[^Tag..], payload, packet[..Header]);
            }
            catch (AuthenticationTagMismatchException) { return null; }
            if (seq > highest)
            {
                seen = seq - highest >= 128 ? 1 : (seen << (int)(seq - highest)) | 1;
                highest = seq;
            }
            else seen |= (UInt128)1 << (int)(highest - seq);
            return payload;
        }
    }
}

static class TapWire
{
    internal const byte Probe = 1, Pong = 2, Ethernet = 3;
    internal static byte[] Frame(byte[] path, byte[] data)
    {
        if (path.Length is < 2 or > 10 || data.Length is < 14 or > TapAdapter.Mtu + 14) throw new ArgumentException("Invalid TAP frame");
        var result = new byte[2 + path.Length + data.Length];
        result[0] = Ethernet; result[1] = (byte)path.Length;
        path.CopyTo(result, 2); data.CopyTo(result, 2 + path.Length);
        return result;
    }

    internal static (byte[] Path, byte[] Frame)? Parse(byte[] payload, byte previous, byte self)
    {
        if (payload is not [Ethernet, >= 2 and <= 10, ..] || payload.Length < 2 + payload[1] + 14 ||
            payload.Length > 2 + payload[1] + 14 + TapAdapter.Mtu) return null;
        var path = payload[2..(2 + payload[1])];
        var position = Array.IndexOf(path, self);
        if (position <= 0 || path[position - 1] != previous ||
            path.Distinct().Count() != path.Length || path.Any(octet => octet is 0 or 255)) return null;
        return (path, payload[(2 + path.Length)..]);
    }

    // Forward only cluster IPv4 and ARP. Use the ARP target IP for request and reply delivery.
    internal static byte? Destination(byte[] frame, byte[] prefix, byte origin)
    {
        if (frame.Length < 14) return null;
        ReadOnlySpan<byte> source, target;
        if (frame[12] == 0x08 && frame[13] == 0x06 && frame.Length >= 42 &&
            frame.AsSpan(14, 6).SequenceEqual(new byte[] { 0, 1, 8, 0, 6, 4 }) &&
            frame[20] == 0 && frame[21] is 1 or 2)
        {
            if (!frame.AsSpan(6, 6).SequenceEqual(frame.AsSpan(22, 6))) return null;
            source = frame.AsSpan(28, 4); target = frame.AsSpan(38, 4);
        }
        else if (frame[12] == 8 && frame[13] == 0 && frame.Length >= 34 && frame[14] >> 4 == 4)
        {
            source = frame.AsSpan(26, 4); target = frame.AsSpan(30, 4);
        }
        else return null;
        return source.StartsWith(prefix) && source[3] == origin && target.StartsWith(prefix) && target[3] is > 0 and < 255 ? target[3] : null;
    }
}
