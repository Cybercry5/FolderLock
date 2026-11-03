using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace FolderLock;

/// Vault format: header (54 bytes, authenticated) + wrapped data key (32) + tag (16),
/// followed by AES-256-GCM chunks (1 MB each) carrying a simple record stream.
public static class Vault
{
    const int ChunkSize = 1 << 20, Tag = 16, NonceLen = 12;
    const int Mem = 65536, Iter = 3, Par = 4;           // Argon2id: 64 MB, 3 passes
    static readonly byte[] Magic = Encoding.ASCII.GetBytes("FLOCK1");

    static byte[] Kdf(string pw, byte[] salt, int mem, int iter, int par)
    {
        var pwb = Encoding.UTF8.GetBytes(pw);
        try
        {
            using var a = new Argon2id(pwb) { Salt = salt, DegreeOfParallelism = par, MemorySize = mem, Iterations = iter };
            return a.GetBytes(32);
        }
        finally { CryptographicOperations.ZeroMemory(pwb); }
    }

    static byte[] Nonce(byte[] prefix, uint c)
    {
        var n = new byte[NonceLen];
        Buffer.BlockCopy(prefix, 0, n, 0, 8);
        n[8] = (byte)(c >> 24); n[9] = (byte)(c >> 16); n[10] = (byte)(c >> 8); n[11] = (byte)c;
        return n;
    }

    // ---------- chunked encrypting writer ----------
    sealed class ChunkWriter : Stream
    {
        readonly Stream _out; readonly AesGcm _aes; readonly byte[] _prefix;
        readonly byte[] _buf = new byte[ChunkSize], _ct = new byte[ChunkSize], _tag = new byte[Tag];
        int _n; uint _ctr;
        public ChunkWriter(Stream o, byte[] key, byte[] prefix) { _out = o; _aes = new AesGcm(key, Tag); _prefix = prefix; }
        public override void Write(byte[] b, int o, int c)
        {
            while (c > 0)
            {
                if (_n == ChunkSize) Emit(false);
                int k = Math.Min(c, ChunkSize - _n);
                Buffer.BlockCopy(b, o, _buf, _n, k); _n += k; o += k; c -= k;
            }
        }
        void Emit(bool fin)
        {
            _aes.Encrypt(Nonce(_prefix, _ctr++), _buf.AsSpan(0, _n), _ct.AsSpan(0, _n), _tag, new[] { (byte)(fin ? 1 : 0) });
            _out.Write(_ct, 0, _n); _out.Write(_tag, 0, Tag); _n = 0;
        }
        public void Finish() { Emit(true); _out.Flush(); }
        public override bool CanRead => false; public override bool CanSeek => false; public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] b, int o, int c) => throw new NotSupportedException();
        public override long Seek(long o, SeekOrigin s) => throw new NotSupportedException();
        public override void SetLength(long v) => throw new NotSupportedException();
        protected override void Dispose(bool d) { if (d) _aes.Dispose(); base.Dispose(d); }
    }

    // ---------- chunked decrypting reader ----------
    sealed class ChunkReader : Stream
    {
        readonly FileStream _in; readonly AesGcm _aes; readonly byte[] _prefix;
        readonly byte[] _raw = new byte[ChunkSize + Tag], _pt = new byte[ChunkSize];
        int _pos, _len; uint _ctr; bool _done;
        public ChunkReader(FileStream i, byte[] key, byte[] prefix) { _in = i; _aes = new AesGcm(key, Tag); _prefix = prefix; }
        bool Fill()
        {
            if (_done) return false;
            long rem = _in.Length - _in.Position;
            if (rem < Tag) throw new InvalidDataException("Vault is truncated or corrupted.");
            int block = (int)Math.Min(rem, ChunkSize + Tag);
            bool fin = rem == block;
            _in.ReadExactly(_raw, 0, block);
            int ctLen = block - Tag;
            try
            {
                _aes.Decrypt(Nonce(_prefix, _ctr++), _raw.AsSpan(0, ctLen), _raw.AsSpan(ctLen, Tag),
                             _pt.AsSpan(0, ctLen), new[] { (byte)(fin ? 1 : 0) });
            }
            catch (CryptographicException) { throw new InvalidDataException("Vault is corrupted or has been tampered with."); }
            _pos = 0; _len = ctLen; if (fin) _done = true;
            return true;
        }
        public override int Read(byte[] b, int o, int c)
        {
            int total = 0;
            while (c > 0)
            {
                if (_pos == _len && !Fill()) break;
                int k = Math.Min(c, _len - _pos);
                Buffer.BlockCopy(_pt, _pos, b, o, k); _pos += k; o += k; c -= k; total += k;
            }
            return total;
        }
        public override bool CanRead => true; public override bool CanSeek => false; public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override void Write(byte[] b, int o, int c) => throw new NotSupportedException();
        public override long Seek(long o, SeekOrigin s) => throw new NotSupportedException();
        public override void SetLength(long v) => throw new NotSupportedException();
        protected override void Dispose(bool d) { if (d) _aes.Dispose(); base.Dispose(d); }
    }

    // ---------- public API ----------
    public static void Lock(string folder, string vaultPath, string password, Action<string> log)
    {
        folder = Path.GetFullPath(folder);
        if (!Directory.Exists(folder)) throw new DirectoryNotFoundException("Folder not found.");
        if (File.Exists(vaultPath)) throw new IOException("A vault with that name already exists.");
        var tmp = vaultPath + ".tmp";

        var dek = RandomNumberGenerator.GetBytes(32);
        try
        {
            try
            {
                log("Deriving key (Argon2id)...");
                WriteVault(folder, tmp, password, dek, log);
                log("Verifying encrypted vault...");
                Extract(tmp, password, null, _ => { });
                File.Move(tmp, vaultPath);
            }
            catch { try { File.Delete(tmp); } catch { } throw; }
        }
        finally { CryptographicOperations.ZeroMemory(dek); }

        log("Removing original folder...");
        Directory.Delete(folder, true);
        log("Done. Folder is locked.");
    }

    static void WriteVault(string folder, string tmp, string password, byte[] dek, Action<string> log)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var prefix = RandomNumberGenerator.GetBytes(8);
        var wnonce = RandomNumberGenerator.GetBytes(12);

        using var hs = new MemoryStream();
        using (var hw = new BinaryWriter(hs, Encoding.UTF8, true))
        {
            hw.Write(Magic); hw.Write(salt); hw.Write(Mem); hw.Write(Iter); hw.Write(Par); hw.Write(prefix); hw.Write(wnonce);
        }
        var aad = hs.ToArray();
        var kek = Kdf(password, salt, Mem, Iter, Par);
        var wrapped = new byte[32]; var wtag = new byte[Tag];
        try { using var w = new AesGcm(kek, Tag); w.Encrypt(wnonce, dek, wrapped, wtag, aad); }
        finally { CryptographicOperations.ZeroMemory(kek); }

        using var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        fs.Write(aad); fs.Write(wrapped); fs.Write(wtag);

        using var cw = new ChunkWriter(fs, dek, prefix);
        using (var bw = new BinaryWriter(cw, Encoding.UTF8, true))
        {
            var opts = new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = 0, IgnoreInaccessible = false };
            foreach (var entry in Directory.EnumerateFileSystemEntries(folder, "*", opts))
            {
                var attr = File.GetAttributes(entry);
                if (attr.HasFlag(FileAttributes.ReparsePoint))
                    throw new NotSupportedException("Symlinks/junctions are not supported: " + entry);
                var rel = Path.GetRelativePath(folder, entry).Replace('\\', '/');
                if (attr.HasFlag(FileAttributes.Directory)) { bw.Write((byte)2); bw.Write(rel); continue; }

                log("Encrypting " + rel);
                using var src = new FileStream(entry, FileMode.Open, FileAccess.Read, FileShare.Read);
                bw.Write((byte)1); bw.Write(rel); bw.Write(src.Length);
                bw.Flush();
                src.CopyTo(cw, 81920);
            }
            bw.Write((byte)0);
        }
        cw.Finish();
        fs.Flush(true);
    }

    /// Decrypts a vault. If destRoot is null, only verifies integrity.
    public static void Extract(string vaultPath, string password, string? destRoot, Action<string> log)
    {
        using var fs = new FileStream(vaultPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        var aad = new byte[54]; fs.ReadExactly(aad);
        var wrapped = new byte[32]; var wtag = new byte[Tag];
        fs.ReadExactly(wrapped); fs.ReadExactly(wtag);

        using var hr = new BinaryReader(new MemoryStream(aad));
        if (!hr.ReadBytes(6).SequenceEqual(Magic)) throw new InvalidDataException("Not a FolderLock vault.");
        var salt = hr.ReadBytes(16); int mem = hr.ReadInt32(), iter = hr.ReadInt32(), par = hr.ReadInt32();
        var prefix = hr.ReadBytes(8); var wnonce = hr.ReadBytes(12);
        if (mem < 8 || mem > (1 << 20) || iter < 1 || iter > 20 || par < 1 || par > 16)
            throw new InvalidDataException("Invalid KDF parameters.");

        var kek = Kdf(password, salt, mem, iter, par);
        var dek = new byte[32];
        try
        {
            using var w = new AesGcm(kek, Tag);
            try { w.Decrypt(wnonce, wrapped, wtag, dek, aad); }
            catch (CryptographicException) { throw new UnauthorizedAccessException("Wrong password (or vault header is damaged)."); }
        }
        finally { CryptographicOperations.ZeroMemory(kek); }

        try
        {
            string? root = destRoot == null ? null : Path.GetFullPath(destRoot).TrimEnd(Path.DirectorySeparatorChar);
            if (root != null) Directory.CreateDirectory(root);

            using var cr = new ChunkReader(fs, dek, prefix);
            using var br = new BinaryReader(cr, Encoding.UTF8, true);
            var buf = new byte[81920];
            while (true)
            {
                byte type = br.ReadByte();
                if (type == 0) break;
                string rel = br.ReadString();
                string? full = null;
                if (root != null)
                {
                    full = Path.GetFullPath(Path.Combine(root, rel));
                    if (!full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException("Unsafe path in vault: " + rel);
                }
                if (type == 2) { if (full != null) Directory.CreateDirectory(full); continue; }
                if (type != 1) throw new InvalidDataException("Unknown record type.");

                long size = br.ReadInt64();
                log("Decrypting " + rel);
                FileStream? o = null;
                if (full != null) { Directory.CreateDirectory(Path.GetDirectoryName(full)!); o = new FileStream(full, FileMode.CreateNew); }
                using (o)
                {
                    while (size > 0)
                    {
                        int n = cr.Read(buf, 0, (int)Math.Min(buf.Length, size));
                        if (n == 0) throw new EndOfStreamException();
                        o?.Write(buf, 0, n); size -= n;
                    }
                }
            }
            if (cr.Read(buf, 0, 1) != 0) throw new InvalidDataException("Unexpected trailing data.");
        }
        finally { CryptographicOperations.ZeroMemory(dek); }
    }
}
