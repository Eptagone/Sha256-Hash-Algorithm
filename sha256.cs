///-------------------------------------------------------------------------
/// Author: Quetzal Rivera          Email: quetzaldev122@outlook.com
/// Bitcoin Donation Address: 3FUskDSShN4kh71NARrsbbWJmsXtWXkrC3
/// Name: Sha256 algorithm        Create Date: 25-12-2017
/// Description: The cryptographic hash function SHA-256 algorithm
/// implemented in C# language
/// Revision History:
/// Name: Creation      Date: 25-12-2017    Descripcion: -
///-------------------------------------------------------------------------
using System;
using System.Linq;

namespace PRUEBA
{
    /// <summary>
    /// Sha256 Class.
    /// </summary>
    class Sha256
    {
        /// <summary>Sha256 instance</summary>
        /// You call a new Sha256 instance with:
        /// <c> Sha256 name = new Sha256(); </c>
        public Sha256() { }

        /// <summary>Hash Function of message.</summary>
        /// <param name="message">Input message to hash</param>
        /// <returns>Hash of the message</returns>
        public byte[] HashComputation(byte[] message)
        {
            /// Step 1: Padding
            /// To ensure that the message has lenght multiple of 512 bits:
            ///     ► First, a bit 1 is appended,
            ///     ► next. k bits 0 e appended, with k being the smallest positive integer
            ///     such that: message + 1 + k + L) mod 512, where L is the initial lenght message.
            ///     ► finally, the lengh L is represented with exactly 64 bits, and these bits are added at
            ///     the end of the message.
            /// The message shall always be padded, even if the initial lenght is already a multiple of 512.
            Byte[] L = BitConverter.GetBytes(Convert.ToUInt64(message.Length * 8)).Reverse().ToArray();
            // 1 byte = 8 bits | mod(%) | When A is multiple of B: A % B = 0
            int k = 0;
            while ((message.Length * 8 + 8 + k + 64) % 512 != 0) { k += 8; }
            byte[] paddedmessage = new byte[(message.Length * 8 + 8 + k + 64) / 8];

            message.CopyTo(paddedmessage, 0);
            paddedmessage[message.Length] = 0x80; // 0x80 = b10000000 = the bit 1
            for (int i = 1; i < (1 + (k / 8)); i++)
                paddedmessage[message.Length + i] = 0x00; // 0x00 = b00000000
            L.CopyTo(paddedmessage, message.Length + 1 + (k / 8));
            
            /// M[i] blocks are formed with paddedmessage.
            /// Each block constains 512 bits of paddedmessage.
            // 64 bytes = 512 bits
            int N = paddedmessage.Length / 64;
            byte[][] M = new byte[N][];
            for (int i = 0; i < N; i++)
            {
                byte[] temp = new byte[64];
                for (int j = 0; j < 64; j++)
                    temp[j] = paddedmessage[(i * 64) + j];
                M[i] = temp;
            }

            /// Step 2: Hash Computation
            ///     ► First, eight variables are set to ther initial values, given by the first 32 bits of the
            ///     fractional part of the square roots of the first 8 prime numbers.
            ///     ► Next, the blocks M[i] are processed one at a time.
            uint[] H = new uint[8];
            H[0] = 0x6a09e667; H[1] = 0xbb67ae85; H[2] = 0x3c6ef372; H[3] = 0xa54ff53a;
            H[4] = 0x510e527f; H[5] = 0x9b05688c; H[6] = 0x1f83d9ab; H[7] = 0x5be0cd19;

            for(int t = 0; t < N; t++)
            {
                /// For each block M, 64 words W[i] are constructed as follows:
                ///     ► the first 16 are obteined by splitting M in 32-bit blocks
                ///         M = W[1] || W[2] || ... || W[15] || W[16]
                ///     ► the remaining 48 are obteined withe formula:
                ///         W[i] = S1(W[i - 2]) + W[i - 7] + S0(W[i - 15]) + W[i - 16]
                uint[] W = new uint[64];
                for (int i = 0, j = 0; i < 16; ++i, j += 4)
                    W[i] = (uint)((M[t][j] << 24) | (M[t][j + 1] << 16) | (M[t][j + 2] << 8) | (M[t][j + 3]));
                for (uint i = 16; i < 64; i++)
                    W[i] = S1(W[i - 2]) + W[i - 7] + S0(W[i - 15]) + W[i - 16];

                uint
                    a = H[0],
                    b = H[1],
                    c = H[2],
                    d = H[3],
                    e = H[4],
                    f = H[5],
                    g = H[6],
                    h = H[7],
                    T1,
                    T2;

                for(int i = 0; i < 64; i++)
                {
                    T1 = h + Z1(e) + Ch(e, f, g) + K[i] + W[i];
                    T2 = Z0(a) + Maj(a, b, c);
                    h = g;
                    g = f;
                    f = e;
                    e = d + T1;
                    d = c;
                    c = b;
                    b = a;
                    a = T1 + T2;
                }

                H[0] = H[0] + a;
                H[1] = H[1] + b;
                H[2] = H[2] + c;
                H[3] = H[3] + d;
                H[4] = H[4] + e;
                H[5] = H[5] + f;
                H[6] = H[6] + g;
                H[7] = H[7] + h;
            }
            /// The has of the message is the concatenation of the new variables H[i]
            /// after the las block has been processed.
            byte[] Hash = new byte[32];
            for (int i = 0; i < 8; i++)
                (BitConverter.GetBytes(H[i]).Reverse().ToArray()).CopyTo(Hash, i * 4);

            return Hash; // Return the final hash of 32 bytes (256 bits)
        }

        // Functions and constans
        /// <summary>Circular right shift of n bits of the binary word a.</summary>
        /// <param name="a">32-bits word </param>
        /// <param name="n">Bits for rotate shift </param>
        /// <returns>A new 32-bits word</returns>
        static uint RotR(uint a, byte n) => (((a) >> (n)) | ((a) << (32 - (n))));
        /// <summary>Right shift of n bits of the binary word a.</summary>
        /// <param name="a">32-bits word </param>
        /// <param name="n"> Bits for rotate shift </param>
        /// <returns>A new 32-bits word</returns>
        static uint ShR(uint a, byte n) => (a >> n);

        private static uint Ch(uint x, uint y, uint z) => (((x) & (y)) ^ ((~x) & (z)));
        private static uint Maj(uint x, uint y, uint z) => (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)));
        private static uint Z0(uint x) => (RotR(x, 2) ^ RotR(x, 13) ^ RotR(x, 22));
        private static uint Z1(uint x) => (RotR(x, 6) ^ RotR(x, 11) ^ RotR(x, 25));
        private static uint S0(uint x) => (RotR(x, 7) ^ RotR(x, 18) ^ ShR(x, 3));
        private static uint S1(uint x) => (RotR(x, 17) ^ RotR(x, 19) ^ ShR(x, 10));
        /// <summary>
        /// The 64 binary words K[i], given by the 32 first bits of the fractional parts
        /// of the cube root of the first 64 prime numbers.
        /// </summary>
        private static uint[] K = { 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    }
}
