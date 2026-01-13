local sha512 = {} do
    local function RightRotate64(hi, lo, n)
        n = n % 64
        if n == 0 then
            return hi, lo
        elseif n < 32 then
            local new_hi = (bit32.rshift(hi, n) + bit32.lshift(lo, 32 - n)) % 2^32
            local new_lo = (bit32.rshift(lo, n) + bit32.lshift(hi, 32 - n)) % 2^32
            return new_hi, new_lo
        elseif n == 32 then
            return lo, hi
        else
            n = n - 32
            local new_hi = (bit32.rshift(lo, n) + bit32.lshift(hi, 32 - n)) % 2^32
            local new_lo = (bit32.rshift(hi, n) + bit32.lshift(lo, 32 - n)) % 2^32
            return new_hi, new_lo
        end
    end

    local function ShiftRight64(hi, lo, n)
        if n == 0 then
            return hi, lo
        elseif n < 32 then
            local new_lo = (bit32.rshift(lo, n) + bit32.lshift(hi, 32 - n)) % 2^32
            local new_hi = bit32.rshift(hi, n)
            return new_hi, new_lo
        elseif n == 32 then
            return 0, hi
        elseif n < 64 then
            n = n - 32
            local new_lo = bit32.rshift(hi, n)
            return 0, new_lo
        else
            return 0, 0
        end
    end

    local function Add64(a_hi, a_lo, b_hi, b_lo)
        local lo = a_lo + b_lo
        local carry = 0
        if lo >= 2^32 then
            lo = lo - 2^32
            carry = 1
        end
        local hi = (a_hi + b_hi + carry) % 2^32
        return hi, lo
    end

    local function Add64_4(a_hi, a_lo, b_hi, b_lo, c_hi, c_lo, d_hi, d_lo)
        local hi, lo = Add64(a_hi, a_lo, b_hi, b_lo)
        hi, lo = Add64(hi, lo, c_hi, c_lo)
        hi, lo = Add64(hi, lo, d_hi, d_lo)
        return hi, lo
    end

    local function Add64_5(a_hi, a_lo, b_hi, b_lo, c_hi, c_lo, d_hi, d_lo, e_hi, e_lo)
        local hi, lo = Add64_4(a_hi, a_lo, b_hi, b_lo, c_hi, c_lo, d_hi, d_lo)
        hi, lo = Add64(hi, lo, e_hi, e_lo)
        return hi, lo
    end

    local function Xor64(a_hi, a_lo, b_hi, b_lo)
        return bit32.bxor(a_hi, b_hi), bit32.bxor(a_lo, b_lo)
    end

    local function And64(a_hi, a_lo, b_hi, b_lo)
        return bit32.band(a_hi, b_hi), bit32.band(a_lo, b_lo)
    end

    local function Not64(a_hi, a_lo)
        return bit32.bnot(a_hi), bit32.bnot(a_lo)
    end

    local function Sigma0(hi, lo)
        local r28_hi, r28_lo = RightRotate64(hi, lo, 28)
        local r34_hi, r34_lo = RightRotate64(hi, lo, 34)
        local r39_hi, r39_lo = RightRotate64(hi, lo, 39)
        local x1_hi, x1_lo = Xor64(r28_hi, r28_lo, r34_hi, r34_lo)
        return Xor64(x1_hi, x1_lo, r39_hi, r39_lo)
    end

    local function Sigma1(hi, lo)
        local r14_hi, r14_lo = RightRotate64(hi, lo, 14)
        local r18_hi, r18_lo = RightRotate64(hi, lo, 18)
        local r41_hi, r41_lo = RightRotate64(hi, lo, 41)
        local x1_hi, x1_lo = Xor64(r14_hi, r14_lo, r18_hi, r18_lo)
        return Xor64(x1_hi, x1_lo, r41_hi, r41_lo)
    end

    local function sigma0(hi, lo)
        local r1_hi, r1_lo = RightRotate64(hi, lo, 1)
        local r8_hi, r8_lo = RightRotate64(hi, lo, 8)
        local s7_hi, s7_lo = ShiftRight64(hi, lo, 7)
        local x1_hi, x1_lo = Xor64(r1_hi, r1_lo, r8_hi, r8_lo)
        return Xor64(x1_hi, x1_lo, s7_hi, s7_lo)
    end

    local function sigma1(hi, lo)
        local r19_hi, r19_lo = RightRotate64(hi, lo, 19)
        local r61_hi, r61_lo = RightRotate64(hi, lo, 61)
        local s6_hi, s6_lo = ShiftRight64(hi, lo, 6)
        local x1_hi, x1_lo = Xor64(r19_hi, r19_lo, r61_hi, r61_lo)
        return Xor64(x1_hi, x1_lo, s6_hi, s6_lo)
    end

    function sha512.hash(message)
        local K = {
            0x428a2f98,0xd728ae22, 0x71374491,0x23ef65cd, 0xb5c0fbcf,0xec4d3b2f, 0xe9b5dba5,0x8189dbbc,
            0x3956c25b,0xf348b538, 0x59f111f1,0xb605d019, 0x923f82a4,0xaf194f9b, 0xab1c5ed5,0xda6d8118,
            0xd807aa98,0xa3030242, 0x12835b01,0x45706fbe, 0x243185be,0x4ee4b28c, 0x550c7dc3,0xd5ffb4e2,
            0x72be5d74,0xf27b896f, 0x80deb1fe,0x3b1696b1, 0x9bdc06a7,0x25c71235, 0xc19bf174,0xcf692694,
            0xe49b69c1,0x9ef14ad2, 0xefbe4786,0x384f25e3, 0x0fc19dc6,0x8b8cd5b5, 0x240ca1cc,0x77ac9c65,
            0x2de92c6f,0x592b0275, 0x4a7484aa,0x6ea6e483, 0x5cb0a9dc,0xbd41fbd4, 0x76f988da,0x831153b5,
            0x983e5152,0xee66dfab, 0xa831c66d,0x2db43210, 0xb00327c8,0x98fb213f, 0xbf597fc7,0xbeef0ee4,
            0xc6e00bf3,0x3da88fc2, 0xd5a79147,0x930aa725, 0x06ca6351,0xe003826f, 0x14292967,0x0a0e6e70,
            0x27b70a85,0x46d22ffc, 0x2e1b2138,0x5c26c926, 0x4d2c6dfc,0x5ac42aed, 0x53380d13,0x9d95b3df,
            0x650a7354,0x8baf63de, 0x766a0abb,0x3c77b2a8, 0x81c2c92e,0x47edaee6, 0x92722c85,0x1482353b,
            0xa2bfe8a1,0x4cf10364, 0xa81a664b,0xbc423001, 0xc24b8b70,0xd0f89791, 0xc76c51a3,0x0654be30,
            0xd192e819,0xd6ef5218, 0xd6990624,0x5565a910, 0xf40e3585,0x5771202a, 0x106aa070,0x32bbd1b8,
            0x19a4c116,0xb8d2d0c8, 0x1e376c08,0x5141ab53, 0x2748774c,0xdf8eeb99, 0x34b0bcb5,0xe19b48a8,
            0x391c0cb3,0xc5c95a63, 0x4ed8aa4a,0xe3418acb, 0x5b9cca4f,0x7763e373, 0x682e6ff3,0xd6b2b8a3,
            0x748f82ee,0x5defb2fc, 0x78a5636f,0x43172f60, 0x84c87814,0xa1f0ab72, 0x8cc70208,0x1a6439ec,
            0x90befffa,0x23631e28, 0xa4506ceb,0xde82bde9, 0xbef9a3f7,0xb2c67915, 0xc67178f2,0xe372532b,
            0xca273ece,0xea26619c, 0xd186b8c7,0x21c0c207, 0xeada7dd6,0xcde0eb1e, 0xf57d4f7f,0xee6ed178,
            0x06f067aa,0x72176fba, 0x0a637dc5,0xa2c898a6, 0x113f9804,0xbef90dae, 0x1b710b35,0x131c471b,
            0x28db77f5,0x23047d84, 0x32caab7b,0x40c72493, 0x3c9ebe0a,0x15c9bebc, 0x431d67c4,0x9c100d4c,
            0x4cc5d4be,0xcb3e42b6, 0x597f299c,0xfc657e2a, 0x5fcb6fab,0x3ad6faec, 0x6c44198c,0x4a475817
        }

        local function Preprocess(message)
            local len = #message
            local bit_len = len * 8

            message = message .. "\128"

            local new_len = #message
            local padding = (112 - (new_len % 128)) % 128
            if padding > 0 then
                message = message .. string.rep("\0", padding)
            end

            local high_hi = 0
            local high_lo = 0
            local low_hi  = math.floor(bit_len / 2^32)
            local low_lo  = bit_len % 2^32

            message = message .. string.char(
                bit32.rshift(high_hi, 24) % 256, bit32.rshift(high_hi, 16) % 256, bit32.rshift(high_hi, 8) % 256, high_hi % 256,
                bit32.rshift(high_lo, 24) % 256, bit32.rshift(high_lo, 16) % 256, bit32.rshift(high_lo, 8) % 256, high_lo % 256,
                bit32.rshift(low_hi,  24) % 256, bit32.rshift(low_hi,  16) % 256, bit32.rshift(low_hi,  8) % 256, low_hi  % 256,
                bit32.rshift(low_lo,  24) % 256, bit32.rshift(low_lo,  16) % 256, bit32.rshift(low_lo,  8) % 256, low_lo  % 256
            )

            return message
        end

        local function Chunkify(message)
            local chunks = {}
            for i = 1, #message, 128 do
                chunks[#chunks + 1] = message:sub(i, i + 127)
            end
            return chunks
        end

        local function ProcessChunk(chunk, H)
            local w_hi = {}
            local w_lo = {}

            for i = 1, 16 do
                local offset = (i - 1) * 8 + 1
                local hi, pos = string.unpack(">I4", chunk, offset)
                local lo = string.unpack(">I4", chunk, pos)
                w_hi[i], w_lo[i] = hi, lo
            end

            for i = 17, 80 do
                local s0_hi, s0_lo = sigma0(w_hi[i - 15], w_lo[i - 15])
                local s1_hi, s1_lo = sigma1(w_hi[i - 2],  w_lo[i - 2])
                local t_hi, t_lo = Add64_4(
                    w_hi[i - 16], w_lo[i - 16],
                    s0_hi, s0_lo,
                    w_hi[i - 7],  w_lo[i - 7],
                    s1_hi, s1_lo
                )
                w_hi[i], w_lo[i] = t_hi, t_lo
            end

            local a_hi, a_lo = H[1], H[2]
            local b_hi, b_lo = H[3], H[4]
            local c_hi, c_lo = H[5], H[6]
            local d_hi, d_lo = H[7], H[8]
            local e_hi, e_lo = H[9], H[10]
            local f_hi, f_lo = H[11], H[12]
            local g_hi, g_lo = H[13], H[14]
            local h_hi, h_lo = H[15], H[16]

            for i = 1, 80 do
                local S1_hi, S1_lo = Sigma1(e_hi, e_lo)
                local ch_hi, ch_lo =
                    And64(e_hi, e_lo, f_hi, f_lo)
                local not_e_hi, not_e_lo = Not64(e_hi, e_lo)
                local t_hi2, t_lo2 =
                    And64(not_e_hi, not_e_lo, g_hi, g_lo)
                ch_hi, ch_lo = Xor64(ch_hi, ch_lo, t_hi2, t_lo2)

                local Ki_hi, Ki_lo = K[(i - 1) * 2 + 1], K[(i - 1) * 2 + 2]

                local temp1_hi, temp1_lo = Add64_5(
                    h_hi, h_lo,
                    S1_hi, S1_lo,
                    ch_hi, ch_lo,
                    Ki_hi, Ki_lo,
                    w_hi[i], w_lo[i]
                )

                local S0_hi, S0_lo = Sigma0(a_hi, a_lo)
                local maj_hi, maj_lo =
                    And64(a_hi, a_lo, b_hi, b_lo)
                local t2_hi, t2_lo =
                    And64(a_hi, a_lo, c_hi, c_lo)
                maj_hi, maj_lo = Xor64(maj_hi, maj_lo, t2_hi, t2_lo)
                local t3_hi, t3_lo =
                    And64(b_hi, b_lo, c_hi, c_lo)
                maj_hi, maj_lo = Xor64(maj_hi, maj_lo, t3_hi, t3_lo)

                local temp2_hi, temp2_lo = Add64(S0_hi, S0_lo, maj_hi, maj_lo)

                h_hi, h_lo = g_hi, g_lo
                g_hi, g_lo = f_hi, f_lo
                f_hi, f_lo = e_hi, e_lo
                e_hi, e_lo = Add64(d_hi, d_lo, temp1_hi, temp1_lo)
                d_hi, d_lo = c_hi, c_lo
                c_hi, c_lo = b_hi, b_lo
                b_hi, b_lo = a_hi, a_lo
                a_hi, a_lo = Add64(temp1_hi, temp1_lo, temp2_hi, temp2_lo)
            end

            H[1],  H[2]  = Add64(H[1],  H[2],  a_hi, a_lo)
            H[3],  H[4]  = Add64(H[3],  H[4],  b_hi, b_lo)
            H[5],  H[6]  = Add64(H[5],  H[6],  c_hi, c_lo)
            H[7],  H[8]  = Add64(H[7],  H[8],  d_hi, d_lo)
            H[9],  H[10] = Add64(H[9],  H[10], e_hi, e_lo)
            H[11], H[12] = Add64(H[11], H[12], f_hi, f_lo)
            H[13], H[14] = Add64(H[13], H[14], g_hi, g_lo)
            H[15], H[16] = Add64(H[15], H[16], h_hi, h_lo)
        end

        message = Preprocess(message)
        local chunks = Chunkify(message)
        
        local H = {
            0x6a09e667,0xf3bcc908,
            0xbb67ae85,0x84caa73b,
            0x3c6ef372,0xfe94f82b,
            0xa54ff53a,0x5f1d36f1,
            0x510e527f,0xade682d1,
            0x9b05688c,0x2b3e6c1f,
            0x1f83d9ab,0xfb41bd6b,
            0x5be0cd19,0x137e2179
        }

        for _, chunk in ipairs(chunks) do
            ProcessChunk(chunk, H)
        end

        local result = ""
        for i = 1, 16, 2 do
            local hi, lo = H[i], H[i + 1]
            result = result .. string.format("%08x%08x", hi, lo)
        end

        return result
    end
end

return sha512
