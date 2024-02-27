-- CryptoNet Networking Framework by SiliconSloth
-- Licensed under the MIT license.
--
-- Copyright (c) 2019 SiliconSloth
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.


-- CryptoNet is a simple and secure framework for encrypted networking
-- between ComputerCraft computers, intended to be used as an alternative to Rednet.
-- For more information, see CryptoNet's GitHub repo at https://github.com/SiliconSloth/CryptoNet

-- Line numbers:
--   48 Third Party
--   53  - SHA-256, HMAC and PBKDF2 functions in ComputerCraft by Anavrins
--  287  - Simple RSA Library by 1lann
-- 1255  - RSA Key Generator by 1lann
-- 1467	 - Mersenne Twister RNG and ISAAC algorithm by KillaVanilla
-- 1724  - AES implementation by KillaVanilla
-- 2691  - Simple thread API by immibis
-- 2771 CryptoNet
-- 2800  - Accessors
-- 2847  - Validity Checks
-- 2952  - Helpers
-- 3276  - Send Functions
-- 3352  - Login System
-- 3904  - Core Networking
-- 4973  - Event Loop
-- 5081  - Certificate Authority


------- THIRD PARTY -------
-- The following code was written by third parties and modified by me (SiliconSloth)
-- to integrate it into CryptoNet. (I shoved everything into tables.)


-- SHA-256, HMAC and PBKDF2 functions in ComputerCraft
-- By Anavrins
-- For help and details, you can PM me on the CC forums
-- You may use this code in your projects without asking me, as long as credit is given and this header is kept intact
-- http://www.computercraft.info/forums2/index.php?/user/12870-anavrins
-- http://pastebin.com/6UV4qfNF
-- Last update: October 10, 2017

-- Usage
---- Data format
------ Almost all arguments passed in these functions can take both a string or a special table containing a byte array.
------ This byte array format is simply a table containing a list of each character's byte values.
------ The phrase "hello world" will become {104,101,108,108,111, 32,119,111,114,108,100}.
------ Any strings can be converted into it with {str:byte(1,-1)}, and back into string with string.char(unpack(arr))
------
------ The data returned by all functions are also in this byte array format.
------ They are paired with a metatable containing metamethods like
------ :toHex() to convert into the traditional hexadecimal representation.
------ :isEqual(arr) to compare the hash with another byte array "arr" in constant time.
------ __tostring to convert into a raw string (Might crash window api on old CC versions).
------ This output can also be fed into my base64 function (TEtna4tX) to get a shorter hash representation.

---- digest(data)
------ The digest function is the core of this API, it simply hashes your data with the SHA256 algorithm, period.
------ It's the function everybody is familiar with, and most likely what you're looking for.
------ This function is mainly used for file integrity, however it is not suited for password storage by itself, use PBKDF2 instead.

---- hmac(data, key)
------ The HMAC function is used for message authentication, it's primary use is in networking apis
------ to authenticate an encrypted message and ensuring that the data was not tempered with.
------ The key may be a string or a byte array, with a size between 0 and 32 bytes (256-bits), having a key larger than 32 bytes will not increase security.
------ This function *may* be used for password storage, if you choose to do so, you must pass the password as the key argument, and the salt as the data argument.

---- PBKDF2(pass, salt, iter, dklen)
------ Password-based key derivation function, returns a "dklen" bytes long array for use in various networking protocol to generate secure cryptographic keys.
------ This is the preferred choice for password storage, it uses individual argument for password and salt, do not concatenate beforehand.
------ This algorithm is designed to inherently slow down hashing by repeating the process many times to slow down cracking attempts.
------ You can adjust the number of "iter" to control the speed of the algorithm, higher "iter" means slower hashing, as well as slower to crack.
------ DO NOT TOUCH "dklen" if you're using it for passwords, simply pass nil or nothing at all (defaults to 32).
------ Passing a dklen higher than 32 will multiply the number of iterations with no additional security whatsoever.

sha256 = {}

sha256.mod32   = 2^32
sha256.band    = bit32 and bit32.band or bit.band
sha256.bnot    = bit32 and bit32.bnot or bit.bnot
sha256.bxor    = bit32 and bit32.bxor or bit.bxor
sha256.blshift = bit32 and bit32.lshift or bit.blshift
sha256.upack   = unpack

sha256.rrotate = function (n, b)
	local s = n/(2^b)
	local f = s%1
	return (s-f) + f*sha256.mod32
end
sha256.brshift = function (int, by) -- Thanks bit32 for bad rshift
	local s = int / (2^by)
	return s - s%1
end

sha256.H = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

sha256.K = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

sha256.counter = function (incr)
	local t1, t2 = 0, 0
	if 0xFFFFFFFF - t1 < incr then
		t2 = t2 + 1
		t1 = incr - (0xFFFFFFFF - t1) - 1
	else t1 = t1 + incr
	end
	return t2, t1
end

sha256.BE_toInt = function (bs, i)
	return sha256.blshift((bs[i] or 0), 24) + sha256.blshift((bs[i+1] or 0), 16) + sha256.blshift((bs[i+2] or 0), 8) + (bs[i+3] or 0)
end

sha256.preprocess = function (data)
	local len = #data
	local proc = {}
	data[#data+1] = 0x80
	while #data%64~=56 do data[#data+1] = 0 end
	local blocks = math.ceil(#data/64)
	for i = 1, blocks do
		proc[i] = {}
		for j = 1, 16 do
			proc[i][j] = sha256.BE_toInt(data, 1+((i-1)*64)+((j-1)*4))
		end
	end
	proc[blocks][15], proc[blocks][16] = sha256.counter(len*8)
	return proc
end

sha256.digestblock = function (w, C)
	for j = 17, 64 do
		local v = w[j-15]
		local s0 = sha256.bxor(sha256.bxor(sha256.rrotate(w[j-15], 7), sha256.rrotate(w[j-15], 18)), sha256.brshift(w[j-15], 3))
		local s1 = sha256.bxor(sha256.bxor(sha256.rrotate(w[j-2], 17), sha256.rrotate(w[j-2], 19)), sha256.brshift(w[j-2], 10))
		w[j] = (w[j-16] + s0 + w[j-7] + s1)%sha256.mod32
	end
	local a, b, c, d, e, f, g, h = sha256.upack(C)
	for j = 1, 64 do
		local S1 = sha256.bxor(sha256.bxor(sha256.rrotate(e, 6), sha256.rrotate(e, 11)), sha256.rrotate(e, 25))
		local ch = sha256.bxor(sha256.band(e, f), sha256.band(sha256.bnot(e), g))
		local temp1 = (h + S1 + ch + sha256.K[j] + w[j])%sha256.mod32
		local S0 = sha256.bxor(sha256.bxor(sha256.rrotate(a, 2), sha256.rrotate(a, 13)), sha256.rrotate(a, 22))
		local maj = sha256.bxor(sha256.bxor(sha256.band(a, b), sha256.band(a, c)), sha256.band(b, c))
		local temp2 = (S0 + maj)%sha256.mod32
		h, g, f, e, d, c, b, a = g, f, e, (d+temp1)%sha256.mod32, c, b, a, (temp1+temp2)%sha256.mod32
	end
	C[1] = (C[1] + a)%sha256.mod32
	C[2] = (C[2] + b)%sha256.mod32
	C[3] = (C[3] + c)%sha256.mod32
	C[4] = (C[4] + d)%sha256.mod32
	C[5] = (C[5] + e)%sha256.mod32
	C[6] = (C[6] + f)%sha256.mod32
	C[7] = (C[7] + g)%sha256.mod32
	C[8] = (C[8] + h)%sha256.mod32
	return C
end

sha256.mt = {
	__tostring = function(a) return string.char(unpack(a)) end,
	__index = {
		toHex = function(self, s) return ("%02x"):rep(#self):format(unpack(self)) end,
		isEqual = function(self, t)
			if type(t) ~= "table" then return false end
			if #self ~= #t then return false end
			local ret = 0
			for i = 1, #self do
				ret = bit32.bor(ret, sha256.bxor(self[i], t[i]))
			end
			return ret == 0
		end
	}
}

sha256.toBytes = function (t, n)
	local b = {}
	for i = 1, n do
		b[(i-1)*4+1] = sha256.band(sha256.brshift(t[i], 24), 0xFF)
		b[(i-1)*4+2] = sha256.band(sha256.brshift(t[i], 16), 0xFF)
		b[(i-1)*4+3] = sha256.band(sha256.brshift(t[i], 8), 0xFF)
		b[(i-1)*4+4] = sha256.band(t[i], 0xFF)
	end
	return setmetatable(b, sha256.mt)
end

sha256.digest = function (data)
	data = data or ""
	data = type(data) == "string" and {data:byte(1,-1)} or data

	data = sha256.preprocess(data)
	local C = {sha256.upack(sha256.H)}
	for i = 1, #data do C = sha256.digestblock(data[i], C) end
	return sha256.toBytes(C, 8)
end

sha256.hmac = function (data, key)
	local data = type(data) == "table" and {sha256.upack(data)} or {tostring(data):byte(1,-1)}
	local key = type(key) == "table" and {sha256.upack(key)} or {tostring(key):byte(1,-1)}

	local blocksize = 64

	key = #key > blocksize and sha256.digest(key) or key

	local ipad = {}
	local opad = {}
	local padded_key = {}

	for i = 1, blocksize do
		ipad[i] = sha256.bxor(0x36, key[i] or 0)
		opad[i] = sha256.bxor(0x5C, key[i] or 0)
	end

	for i = 1, #data do
		ipad[blocksize+i] = data[i]
	end

	ipad = sha256.digest(ipad)

	for i = 1, blocksize do
		padded_key[i] = opad[i]
		padded_key[blocksize+i] = ipad[i]
	end

	return sha256.digest(padded_key)
end

sha256.pbkdf2 = function (pass, salt, iter, dklen)
	local salt = type(salt) == "table" and salt or {tostring(salt):byte(1,-1)}
	local hashlen = 32
	local dklen = dklen or 32
	local block = 1
	local out = {}

	while dklen > 0 do
		local ikey = {}
		local isalt = {sha256.upack(salt)}
		local clen = dklen > hashlen and hashlen or dklen

		isalt[#isalt+1] = sha256.band(sha256.brshift(block, 24), 0xFF)
		isalt[#isalt+1] = sha256.band(sha256.brshift(block, 16), 0xFF)
		isalt[#isalt+1] = sha256.band(sha256.brshift(block, 8), 0xFF)
		isalt[#isalt+1] = sha256.band(block, 0xFF)

		for j = 1, iter do
			isalt = sha256.hmac(isalt, pass)
			for k = 1, clen do ikey[k] = sha256.bxor(isalt[k], ikey[k] or 0) end
			if j % 200 == 0 then os.queueEvent("PBKDF2", j) coroutine.yield("PBKDF2") end
		end
		dklen = dklen - clen
		block = block+1
		for k = 1, clen do out[#out+1] = ikey[k] end
	end

	return setmetatable(out, sha256.mt)
end


--
-- Licenses for Simple RSA Library by 1lann
--
-- This RSA library should not be used for real-life purposes.
-- It is here to demonstrate a pure Lua implementation of RSA
-- for educational purposes. This RSA library is in no way
-- secure and does not endorse use of this library for any
-- actual security purposes.
--
-- Copyright (c) 2015 Jason Chu (1lann)
--
-- Permission to use, copy, modify, and distribute this software for any
-- purpose with or without fee is hereby granted, provided that the above
-- copyright notice and this permission notice appear in all copies.
--
-- THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
-- WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
-- MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
-- ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
-- WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
-- ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
-- OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
--

--
-- Big Integer Library, copyright as follows.
--
-- Copyright (c) 2010 Ted Unangst <ted.unangst@gmail.com>
--
-- Permission to use, copy, modify, and distribute this software for any
-- purpose with or without fee is hereby granted, provided that the above
-- copyright notice and this permission notice appear in all copies.
--
-- THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
-- WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
-- MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
-- ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
-- WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
-- ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
-- OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
--

--
-- Lua version ported/copied from the C version of the Big Integer Library, copyright as follows.
--
-- Copyright (c) 2000 by Jef Poskanzer <jef@mail.acme.com>.
-- All rights reserved.
--
-- Redistribution and use in source and binary forms, with or without
-- modification, are permitted provided that the following conditions
-- are met:
-- 1. Redistributions of source code must retain the above copyright
--    notice, this list of conditions and the following disclaimer.
-- 2. Redistributions in binary form must reproduce the above copyright
--    notice, this list of conditions and the following disclaimer in the
--    documentation and/or other materials provided with the distribution.
--
-- THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
-- ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
-- IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
-- ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
-- FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
-- DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
-- OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
-- HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
-- LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
-- OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
-- SUCH DAMAGE.
--


--
-- RSA Encryption/Decryption Library
-- By 1lann
--
-- Refer to license: http://pastebin.com/9gWSyqQt
--

rsaCrypt = {}

--
-- Start of third-party libraries/helpers
--

-- two functions to help make Lua act more like C
rsaCrypt.fl = function (x)
	if x < 0 then
		return math.ceil(x) + 0 -- make -0 go away
	else
		return math.floor(x)
	end
end

rsaCrypt.cmod = function (a, b)
	local x = a % b
	if a < 0 and x > 0 then
		x = x - b
	end
	return x
end


rsaCrypt.radix = 2^24 -- maybe up to 2^26 is safe?
rsaCrypt.radix_sqrt = rsaCrypt.fl(math.sqrt(rsaCrypt.radix))

rsaCrypt.alloc = function ()
	local bi = {}
	setmetatable(bi, rsaCrypt.bigintmt)
	bi.comps = {}
	bi.sign = 1;
	return bi
end

rsaCrypt.clone = function (a)
	local bi = rsaCrypt.alloc()
	bi.sign = a.sign
	local c = bi.comps
	local ac = a.comps
	for i = 1, #ac do
		c[i] = ac[i]
	end
	return bi
end

rsaCrypt.normalize = function (bi, notrunc)
	local c = bi.comps
	local v
	-- borrow for negative components
	for i = 1, #c - 1 do
		v = c[i]
		if v < 0 then
			c[i+1] = c[i+1] + rsaCrypt.fl(v / rsaCrypt.radix) - 1
			v = rsaCrypt.cmod(v, rsaCrypt.radix)
			if v ~= 0 then
				c[i] = v + rsaCrypt.radix
			else
				c[i] = v
				c[i+1] = c[i+1] + 1
			end
		end
	end
	-- is top component negative?
	if c[#c] < 0 then
		-- switch the sign and fix components
		bi.sign = -bi.sign
		for i = 1, #c - 1 do
			v = c[i]
			c[i] = rsaCrypt.radix - v
			c[i+1] = c[i+1] + 1
		end
		c[#c] = -c[#c]
	end
	-- carry for components larger than radix
	for i = 1, #c do
		v = c[i]
		if v > rsaCrypt.radix then
			c[i+1] = (c[i+1] or 0) + rsaCrypt.fl(v / rsaCrypt.radix)
			c[i] = rsaCrypt.cmod(v, rsaCrypt.radix)
		end
	end
	-- trim off leading zeros
	if not notrunc then
		for i = #c, 2, -1 do
			if c[i] == 0 then
				c[i] = nil
			else
				break
			end
		end
	end
	-- check for -0
	if #c == 1 and c[1] == 0 and bi.sign == -1 then
		bi.sign = 1
	end
end

rsaCrypt.negate = function (a)
	local bi = rsaCrypt.clone(a)
	bi.sign = -bi.sign
	return bi
end

rsaCrypt.compare = function (a, b)
	local ac, bc = a.comps, b.comps
	local as, bs = a.sign, b.sign
	if ac == bc then
		return 0
	elseif as > bs then
		return 1
	elseif as < bs then
		return -1
	elseif #ac > #bc then
		return as
	elseif #ac < #bc then
		return -as
	end
	for i = #ac, 1, -1 do
		if ac[i] > bc[i] then
			return as
		elseif ac[i] < bc[i] then
			return -as
		end
	end
	return 0
end

rsaCrypt.lt = function (a, b)
	return rsaCrypt.compare(a, b) < 0
end

rsaCrypt.eq = function (a, b)
	return rsaCrypt.compare(a, b) == 0
end

rsaCrypt.le = function (a, b)
	return rsaCrypt.compare(a, b) <= 0
end

rsaCrypt.addint = function (a, n)
	local bi = rsaCrypt.clone(a)
	if bi.sign == 1 then
		bi.comps[1] = bi.comps[1] + n
	else
		bi.comps[1] = bi.comps[1] - n
	end
	rsaCrypt.normalize(bi)
	return bi
end

rsaCrypt.add = function (a, b)
	if type(a) == "number" then
		return rsaCrypt.addint(b, a)
	elseif type(b) == "number" then
		return rsaCrypt.addint(a, b)
	end
	local bi = rsaCrypt.clone(a)
	local sign = bi.sign == b.sign
	local c = bi.comps
	for i = #c + 1, #b.comps do
		c[i] = 0
	end
	local bc = b.comps
	for i = 1, #bc do
		local v = bc[i]
		if sign then
			c[i] = c[i] + v
		else
			c[i] = c[i] - v
		end
	end
	rsaCrypt.normalize(bi)
	return bi
end

rsaCrypt.sub = function (a, b)
	if type(b) == "number" then
		return rsaCrypt.addint(a, -b)
	elseif type(a) == "number" then
		a = rsaCrypt.bigint(a)
	end
	return rsaCrypt.add(a, rsaCrypt.negate(b))
end

rsaCrypt.mulint = function (a, b)
	local bi = rsaCrypt.clone(a)
	if b < 0 then
		b = -b
		bi.sign = -bi.sign
	end
	local bc = bi.comps
	for i = 1, #bc do
		bc[i] = bc[i] * b
	end
	rsaCrypt.normalize(bi)
	return bi
end

rsaCrypt.multiply = function (a, b)
	local bi = rsaCrypt.alloc()
	local c = bi.comps
	local ac, bc = a.comps, b.comps
	for i = 1, #ac + #bc do
		c[i] = 0
	end
	for i = 1, #ac do
		for j = 1, #bc do
			c[i+j-1] = c[i+j-1] + ac[i] * bc[j]
		end
		-- keep the zeroes
		rsaCrypt.normalize(bi, true)
	end
	rsaCrypt.normalize(bi)
	if bi ~= rsaCrypt.bigint(0) then
		bi.sign = a.sign * b.sign
	end
	return bi
end

rsaCrypt.kmul = function (a, b)
	local ac, bc = a.comps, b.comps
	local an, bn = #a.comps, #b.comps
	local bi, bj, bk, bl = rsaCrypt.alloc(), rsaCrypt.alloc(), rsaCrypt.alloc(), rsaCrypt.alloc()
	local ic, jc, kc, lc = bi.comps, bj.comps, bk.comps, bl.comps

	local n = rsaCrypt.fl((math.max(an, bn) + 1) / 2)
	for i = 1, n do
		ic[i] = (i + n <= an) and ac[i+n] or 0
		jc[i] = (i <= an) and ac[i] or 0
		kc[i] = (i + n <= bn) and bc[i+n] or 0
		lc[i] = (i <= bn) and bc[i] or 0
	end
	rsaCrypt.normalize(bi)
	rsaCrypt.normalize(bj)
	rsaCrypt.normalize(bk)
	rsaCrypt.normalize(bl)
	local ik = bi * bk
	local jl = bj * bl
	local mid = (bi + bj) * (bk + bl) - ik - jl
	local mc = mid.comps
	local ikc = ik.comps
	local jlc = jl.comps
	for i = 1, #ikc + n*2 do -- fill it up
		jlc[i] = jlc[i] or 0
	end
	for i = 1, #mc do
		jlc[i+n] = jlc[i+n] + mc[i]
	end
	for i = 1, #ikc do
		jlc[i+n*2] = jlc[i+n*2] + ikc[i]
	end
	jl.sign = a.sign * b.sign
	rsaCrypt.normalize(jl)
	return jl
end

rsaCrypt.kthresh = 12

rsaCrypt.mul = function (a, b)
	if type(a) == "number" then
		return rsaCrypt.mulint(b, a)
	elseif type(b) == "number" then
		return rsaCrypt.mulint(a, b)
	end
	if #a.comps < rsaCrypt.kthresh or #b.comps < rsaCrypt.kthresh then
		return rsaCrypt.multiply(a, b)
	end
	return rsaCrypt.kmul(a, b)
end

rsaCrypt.divint = function (numer, denom)
	local bi = rsaCrypt.clone(numer)
	if denom < 0 then
		denom = -denom
		bi.sign = -bi.sign
	end
	local r = 0
	local c = bi.comps
	for i = #c, 1, -1 do
		r = r * rsaCrypt.radix + c[i]
		c[i] = rsaCrypt.fl(r / denom)
		r = rsaCrypt.cmod(r, denom)
	end
	rsaCrypt.normalize(bi)
	return bi
end

rsaCrypt.multi_divide = function (numer, denom)
	local n = #denom.comps
	local approx = rsaCrypt.divint(numer, denom.comps[n])
	for i = n, #approx.comps do
		approx.comps[i - n + 1] = approx.comps[i]
	end
	for i = #approx.comps, #approx.comps - n + 2, -1 do
		approx.comps[i] = nil
	end
	local rem = approx * denom - numer
	if rem < denom then
		quotient = approx
	else
		quotient = approx - rsaCrypt.multi_divide(rem, denom)
	end
	return quotient
end

rsaCrypt.multi_divide_wrap = function (numer, denom)
	-- we use a successive approximation method, but it doesn't work
	-- if the high order component is too small.  adjust if needed.
	if denom.comps[#denom.comps] < rsaCrypt.radix_sqrt then
		numer = rsaCrypt.mulint(numer, rsaCrypt.radix_sqrt)
		denom = rsaCrypt.mulint(denom, rsaCrypt.radix_sqrt)
	end
	return rsaCrypt.multi_divide(numer, denom)
end

rsaCrypt.div = function (numer, denom)
	if type(denom) == "number" then
		if denom == 0 then
			error("divide by 0", 2)
		end
		return rsaCrypt.divint(numer, denom)
	elseif type(numer) == "number" then
		numer = rsaCrypt.bigint(numer)
	end
	-- check signs and trivial cases
	local sign = 1
	local cmp = rsaCrypt.compare(denom, rsaCrypt.bigint(0))
	if cmp == 0 then
		error("divide by 0", 2)
	elseif cmp == -1 then
		sign = -sign
		denom = rsaCrypt.negate(denom)
	end
	cmp = rsaCrypt.compare(numer, rsaCrypt.bigint(0))
	if cmp == 0 then
		return rsaCrypt.bigint(0)
	elseif cmp == -1 then
		sign = -sign
		numer = rsaCrypt.negate(numer)
	end
	cmp = rsaCrypt.compare(numer, denom)
	if cmp == -1 then
		return rsaCrypt.bigint(0)
	elseif cmp == 0 then
		return rsaCrypt.bigint(sign)
	end
	local bi
	-- if small enough, do it the easy way
	if #denom.comps == 1 then
		bi = rsaCrypt.divint(numer, denom.comps[1])
	else
		bi = rsaCrypt.multi_divide_wrap(numer, denom)
	end
	if sign == -1 then
		bi = rsaCrypt.negate(bi)
	end
	return bi
end

rsaCrypt.intrem = function (bi, m)
	if m < 0 then
		m = -m
	end
	local rad_r = 1
	local r = 0
	local bc = bi.comps
	for i = 1, #bc do
		local v = bc[i]
		r = rsaCrypt.cmod(r + v * rad_r, m)
		rad_r = rsaCrypt.cmod(rad_r * rsaCrypt.radix, m)
	end
	if bi.sign < 1 then
		r = -r
	end
	return r
end

rsaCrypt.intmod = function (bi, m)
	local r = rsaCrypt.intrem(bi, m)
	if r < 0 then
		r = r + m
	end
	return r
end

rsaCrypt.rem = function (bi, m)
	if type(m) == "number" then
		return rsaCrypt.bigint(rsaCrypt.intrem(bi, m))
	elseif type(bi) == "number" then
		bi = rsaCrypt.bigint(bi)
	end

	return bi - ((bi / m) * m)
end

rsaCrypt.mod = function (a, m)
	local bi = rsaCrypt.rem(a, m)
	if bi.sign == -1 then
		bi = bi + m
	end
	return bi
end

rsaCrypt.printscale = 10000000
rsaCrypt.printscalefmt = string.format("%%.%dd", math.log10(rsaCrypt.printscale))
rsaCrypt.makestr = function (bi, s)
	if bi >= rsaCrypt.bigint(rsaCrypt.printscale) then
		rsaCrypt.makestr(rsaCrypt.divint(bi, rsaCrypt.printscale), s)
	end
	table.insert(s, string.format(rsaCrypt.printscalefmt, rsaCrypt.intmod(bi, rsaCrypt.printscale)))
end

rsaCrypt.biginttostring =  function (bi)
	local s = {}
	if bi < rsaCrypt.bigint(0) then
		bi = rsaCrypt.negate(bi)
		table.insert(s, "-")
	end
	rsaCrypt.makestr(bi, s)
	s = table.concat(s):gsub("^0*", "")
	if s == "" then s = "0" end
	return s
end

rsaCrypt.biginttonumber = function (bi)
	return tonumber(rsaCrypt.biginttostring(bi))
end

rsaCrypt.bigintmt = {
	__add = rsaCrypt.add,
	__sub = rsaCrypt.sub,
	__mul = rsaCrypt.mul,
	__div = rsaCrypt.div,
	__mod = rsaCrypt.mod,
	__unm = rsaCrypt.negate,
	__eq = rsaCrypt.eq,
	__lt = rsaCrypt.lt,
	__le = rsaCrypt.le,
	__tostring = rsaCrypt.biginttostring,
}

rsaCrypt.cache = {}
rsaCrypt.ncache = 0

rsaCrypt.bigint = function (n)
	if rsaCrypt.cache[n] then
		return rsaCrypt.cache[n]
	end
	local bi
	if type(n) == "string" then
		local digits = { n:byte(1, -1) }
		for i = 1, #digits do
			digits[i] = string.char(digits[i])
		end
		local start = 1
		local sign = 1
		if digits[i] == '-' then
			sign = -1
			start = 2
		end
		bi = rsaCrypt.bigint(0)
		for i = start, #digits do
			bi = rsaCrypt.addint(rsaCrypt.mulint(bi, 10), tonumber(digits[i]))
		end
		bi = rsaCrypt.mulint(bi, sign)
	else
		bi = rsaCrypt.alloc()
		bi.comps[1] = n
		rsaCrypt.normalize(bi)
	end
	if rsaCrypt.ncache > 100 then
		rsaCrypt.cache = {}
		rsaCrypt.ncache = 0
	end
	rsaCrypt.cache[n] = bi
	rsaCrypt.ncache = rsaCrypt.ncache + 1
	return bi
end

--
-- Start of my code
--

rsaCrypt.powersTwo = {
rsaCrypt.bigint("2"),
rsaCrypt.bigint("4"),
rsaCrypt.bigint("8"),
rsaCrypt.bigint("16"),
rsaCrypt.bigint("32"),
rsaCrypt.bigint("64"),
rsaCrypt.bigint("128"),
rsaCrypt.bigint("256"),
rsaCrypt.bigint("512"),
rsaCrypt.bigint("1024"),
rsaCrypt.bigint("2048"),
rsaCrypt.bigint("4096"),
rsaCrypt.bigint("8192"),
rsaCrypt.bigint("16384"),
rsaCrypt.bigint("32768"),
rsaCrypt.bigint("65536"),
rsaCrypt.bigint("131072"),
rsaCrypt.bigint("262144"),
rsaCrypt.bigint("524288"),
rsaCrypt.bigint("1048576"),
rsaCrypt.bigint("2097152"),
rsaCrypt.bigint("4194304"),
rsaCrypt.bigint("8388608"),
rsaCrypt.bigint("16777216"),
rsaCrypt.bigint("33554432"),
rsaCrypt.bigint("67108864"),
rsaCrypt.bigint("134217728"),
rsaCrypt.bigint("268435456"),
rsaCrypt.bigint("536870912"),
rsaCrypt.bigint("1073741824"),
rsaCrypt.bigint("2147483648"),
rsaCrypt.bigint("4294967296"),
rsaCrypt.bigint("8589934592"),
rsaCrypt.bigint("17179869184"),
rsaCrypt.bigint("34359738368"),
rsaCrypt.bigint("68719476736"),
rsaCrypt.bigint("137438953472"),
rsaCrypt.bigint("274877906944"),
rsaCrypt.bigint("549755813888"),
rsaCrypt.bigint("1099511627776"),
rsaCrypt.bigint("2199023255552"),
rsaCrypt.bigint("4398046511104"),
rsaCrypt.bigint("8796093022208"),
rsaCrypt.bigint("17592186044416"),
rsaCrypt.bigint("35184372088832"),
rsaCrypt.bigint("70368744177664"),
rsaCrypt.bigint("140737488355328"),
rsaCrypt.bigint("281474976710656"),
rsaCrypt.bigint("562949953421312"),
rsaCrypt.bigint("1125899906842624"),
rsaCrypt.bigint("2251799813685248"),
rsaCrypt.bigint("4503599627370496"),
rsaCrypt.bigint("9007199254740992"),
rsaCrypt.bigint("18014398509481984"),
rsaCrypt.bigint("36028797018963968"),
rsaCrypt.bigint("72057594037927936"),
rsaCrypt.bigint("144115188075855872"),
rsaCrypt.bigint("288230376151711744"),
rsaCrypt.bigint("576460752303423488"),
rsaCrypt.bigint("1152921504606846976"),
rsaCrypt.bigint("2305843009213693952"),
rsaCrypt.bigint("4611686018427387904"),
rsaCrypt.bigint("9223372036854775808"),
rsaCrypt.bigint("18446744073709551616"),
rsaCrypt.bigint("36893488147419103232"),
rsaCrypt.bigint("73786976294838206464"),
rsaCrypt.bigint("147573952589676412928"),
rsaCrypt.bigint("295147905179352825856"),
rsaCrypt.bigint("590295810358705651712"),
rsaCrypt.bigint("1180591620717411303424"),
rsaCrypt.bigint("2361183241434822606848"),
rsaCrypt.bigint("4722366482869645213696"),
rsaCrypt.bigint("9444732965739290427392"),
rsaCrypt.bigint("18889465931478580854784"),
rsaCrypt.bigint("37778931862957161709568"),
rsaCrypt.bigint("75557863725914323419136"),
rsaCrypt.bigint("151115727451828646838272"),
rsaCrypt.bigint("302231454903657293676544"),
rsaCrypt.bigint("604462909807314587353088"),
rsaCrypt.bigint("1208925819614629174706176"),
rsaCrypt.bigint("2417851639229258349412352"),
rsaCrypt.bigint("4835703278458516698824704"),
rsaCrypt.bigint("9671406556917033397649408"),
rsaCrypt.bigint("19342813113834066795298816"),
rsaCrypt.bigint("38685626227668133590597632"),
rsaCrypt.bigint("77371252455336267181195264"),
rsaCrypt.bigint("154742504910672534362390528"),
rsaCrypt.bigint("309485009821345068724781056"),
rsaCrypt.bigint("618970019642690137449562112"),
rsaCrypt.bigint("1237940039285380274899124224"),
rsaCrypt.bigint("2475880078570760549798248448"),
rsaCrypt.bigint("4951760157141521099596496896"),
rsaCrypt.bigint("9903520314283042199192993792"),
rsaCrypt.bigint("19807040628566084398385987584"),
rsaCrypt.bigint("39614081257132168796771975168"),
rsaCrypt.bigint("79228162514264337593543950336"),
rsaCrypt.bigint("158456325028528675187087900672"),
rsaCrypt.bigint("316912650057057350374175801344"),
rsaCrypt.bigint("633825300114114700748351602688"),
rsaCrypt.bigint("1267650600228229401496703205376"),
rsaCrypt.bigint("2535301200456458802993406410752"),
rsaCrypt.bigint("5070602400912917605986812821504"),
rsaCrypt.bigint("10141204801825835211973625643008"),
rsaCrypt.bigint("20282409603651670423947251286016"),
rsaCrypt.bigint("40564819207303340847894502572032"),
rsaCrypt.bigint("81129638414606681695789005144064"),
rsaCrypt.bigint("162259276829213363391578010288128"),
rsaCrypt.bigint("324518553658426726783156020576256"),
rsaCrypt.bigint("649037107316853453566312041152512"),
rsaCrypt.bigint("1298074214633706907132624082305024"),
rsaCrypt.bigint("2596148429267413814265248164610048"),
rsaCrypt.bigint("5192296858534827628530496329220096"),
rsaCrypt.bigint("10384593717069655257060992658440192"),
rsaCrypt.bigint("20769187434139310514121985316880384"),
rsaCrypt.bigint("41538374868278621028243970633760768"),
rsaCrypt.bigint("83076749736557242056487941267521536"),
rsaCrypt.bigint("166153499473114484112975882535043072"),
rsaCrypt.bigint("332306998946228968225951765070086144"),
rsaCrypt.bigint("664613997892457936451903530140172288"),
rsaCrypt.bigint("1329227995784915872903807060280344576"),
rsaCrypt.bigint("2658455991569831745807614120560689152"),
rsaCrypt.bigint("5316911983139663491615228241121378304"),
rsaCrypt.bigint("10633823966279326983230456482242756608"),
rsaCrypt.bigint("21267647932558653966460912964485513216"),
rsaCrypt.bigint("42535295865117307932921825928971026432"),
rsaCrypt.bigint("85070591730234615865843651857942052864"),
rsaCrypt.bigint("170141183460469231731687303715884105728"),
rsaCrypt.bigint("340282366920938463463374607431768211456"),
rsaCrypt.bigint("680564733841876926926749214863536422912"),
rsaCrypt.bigint("1361129467683753853853498429727072845824"),
rsaCrypt.bigint("2722258935367507707706996859454145691648"),
rsaCrypt.bigint("5444517870735015415413993718908291383296"),
rsaCrypt.bigint("10889035741470030830827987437816582766592"),
rsaCrypt.bigint("21778071482940061661655974875633165533184"),
rsaCrypt.bigint("43556142965880123323311949751266331066368"),
rsaCrypt.bigint("87112285931760246646623899502532662132736"),
rsaCrypt.bigint("174224571863520493293247799005065324265472"),
rsaCrypt.bigint("348449143727040986586495598010130648530944"),
rsaCrypt.bigint("696898287454081973172991196020261297061888"),
rsaCrypt.bigint("1393796574908163946345982392040522594123776"),
rsaCrypt.bigint("2787593149816327892691964784081045188247552"),
rsaCrypt.bigint("5575186299632655785383929568162090376495104"),
rsaCrypt.bigint("11150372599265311570767859136324180752990208"),
rsaCrypt.bigint("22300745198530623141535718272648361505980416"),
rsaCrypt.bigint("44601490397061246283071436545296723011960832"),
rsaCrypt.bigint("89202980794122492566142873090593446023921664"),
rsaCrypt.bigint("178405961588244985132285746181186892047843328"),
rsaCrypt.bigint("356811923176489970264571492362373784095686656"),
rsaCrypt.bigint("713623846352979940529142984724747568191373312"),
rsaCrypt.bigint("1427247692705959881058285969449495136382746624"),
rsaCrypt.bigint("2854495385411919762116571938898990272765493248"),
rsaCrypt.bigint("5708990770823839524233143877797980545530986496"),
rsaCrypt.bigint("11417981541647679048466287755595961091061972992"),
rsaCrypt.bigint("22835963083295358096932575511191922182123945984"),
rsaCrypt.bigint("45671926166590716193865151022383844364247891968"),
rsaCrypt.bigint("91343852333181432387730302044767688728495783936"),
rsaCrypt.bigint("182687704666362864775460604089535377456991567872"),
rsaCrypt.bigint("365375409332725729550921208179070754913983135744"),
rsaCrypt.bigint("730750818665451459101842416358141509827966271488"),
rsaCrypt.bigint("1461501637330902918203684832716283019655932542976"),
rsaCrypt.bigint("2923003274661805836407369665432566039311865085952"),
rsaCrypt.bigint("5846006549323611672814739330865132078623730171904"),
rsaCrypt.bigint("11692013098647223345629478661730264157247460343808"),
rsaCrypt.bigint("23384026197294446691258957323460528314494920687616"),
rsaCrypt.bigint("46768052394588893382517914646921056628989841375232"),
rsaCrypt.bigint("93536104789177786765035829293842113257979682750464"),
rsaCrypt.bigint("187072209578355573530071658587684226515959365500928"),
rsaCrypt.bigint("374144419156711147060143317175368453031918731001856"),
rsaCrypt.bigint("748288838313422294120286634350736906063837462003712"),
rsaCrypt.bigint("1496577676626844588240573268701473812127674924007424"),
rsaCrypt.bigint("2993155353253689176481146537402947624255349848014848"),
rsaCrypt.bigint("5986310706507378352962293074805895248510699696029696"),
rsaCrypt.bigint("11972621413014756705924586149611790497021399392059392"),
rsaCrypt.bigint("23945242826029513411849172299223580994042798784118784"),
rsaCrypt.bigint("47890485652059026823698344598447161988085597568237568"),
rsaCrypt.bigint("95780971304118053647396689196894323976171195136475136"),
rsaCrypt.bigint("191561942608236107294793378393788647952342390272950272"),
rsaCrypt.bigint("383123885216472214589586756787577295904684780545900544"),
rsaCrypt.bigint("766247770432944429179173513575154591809369561091801088"),
rsaCrypt.bigint("1532495540865888858358347027150309183618739122183602176"),
rsaCrypt.bigint("3064991081731777716716694054300618367237478244367204352"),
rsaCrypt.bigint("6129982163463555433433388108601236734474956488734408704"),
rsaCrypt.bigint("12259964326927110866866776217202473468949912977468817408"),
rsaCrypt.bigint("24519928653854221733733552434404946937899825954937634816"),
rsaCrypt.bigint("49039857307708443467467104868809893875799651909875269632"),
rsaCrypt.bigint("98079714615416886934934209737619787751599303819750539264"),
rsaCrypt.bigint("196159429230833773869868419475239575503198607639501078528"),
rsaCrypt.bigint("392318858461667547739736838950479151006397215279002157056"),
rsaCrypt.bigint("784637716923335095479473677900958302012794430558004314112"),
rsaCrypt.bigint("1569275433846670190958947355801916604025588861116008628224"),
rsaCrypt.bigint("3138550867693340381917894711603833208051177722232017256448"),
rsaCrypt.bigint("6277101735386680763835789423207666416102355444464034512896"),
rsaCrypt.bigint("12554203470773361527671578846415332832204710888928069025792"),
rsaCrypt.bigint("25108406941546723055343157692830665664409421777856138051584"),
rsaCrypt.bigint("50216813883093446110686315385661331328818843555712276103168"),
rsaCrypt.bigint("100433627766186892221372630771322662657637687111424552206336"),
rsaCrypt.bigint("200867255532373784442745261542645325315275374222849104412672"),
rsaCrypt.bigint("401734511064747568885490523085290650630550748445698208825344"),
rsaCrypt.bigint("803469022129495137770981046170581301261101496891396417650688"),
rsaCrypt.bigint("1606938044258990275541962092341162602522202993782792835301376"),
rsaCrypt.bigint("3213876088517980551083924184682325205044405987565585670602752"),
rsaCrypt.bigint("6427752177035961102167848369364650410088811975131171341205504"),
rsaCrypt.bigint("12855504354071922204335696738729300820177623950262342682411008"),
rsaCrypt.bigint("25711008708143844408671393477458601640355247900524685364822016"),
rsaCrypt.bigint("51422017416287688817342786954917203280710495801049370729644032"),
rsaCrypt.bigint("102844034832575377634685573909834406561420991602098741459288064"),
rsaCrypt.bigint("205688069665150755269371147819668813122841983204197482918576128"),
rsaCrypt.bigint("411376139330301510538742295639337626245683966408394965837152256"),
rsaCrypt.bigint("822752278660603021077484591278675252491367932816789931674304512"),
rsaCrypt.bigint("1645504557321206042154969182557350504982735865633579863348609024"),
rsaCrypt.bigint("3291009114642412084309938365114701009965471731267159726697218048"),
rsaCrypt.bigint("6582018229284824168619876730229402019930943462534319453394436096"),
rsaCrypt.bigint("13164036458569648337239753460458804039861886925068638906788872192"),
rsaCrypt.bigint("26328072917139296674479506920917608079723773850137277813577744384"),
rsaCrypt.bigint("52656145834278593348959013841835216159447547700274555627155488768"),
rsaCrypt.bigint("105312291668557186697918027683670432318895095400549111254310977536"),
rsaCrypt.bigint("210624583337114373395836055367340864637790190801098222508621955072"),
rsaCrypt.bigint("421249166674228746791672110734681729275580381602196445017243910144"),
rsaCrypt.bigint("842498333348457493583344221469363458551160763204392890034487820288"),
rsaCrypt.bigint("1684996666696914987166688442938726917102321526408785780068975640576"),
rsaCrypt.bigint("3369993333393829974333376885877453834204643052817571560137951281152"),
rsaCrypt.bigint("6739986666787659948666753771754907668409286105635143120275902562304"),
rsaCrypt.bigint("13479973333575319897333507543509815336818572211270286240551805124608"),
rsaCrypt.bigint("26959946667150639794667015087019630673637144422540572481103610249216"),
rsaCrypt.bigint("53919893334301279589334030174039261347274288845081144962207220498432"),
rsaCrypt.bigint("107839786668602559178668060348078522694548577690162289924414440996864"),
rsaCrypt.bigint("215679573337205118357336120696157045389097155380324579848828881993728"),
rsaCrypt.bigint("431359146674410236714672241392314090778194310760649159697657763987456"),
rsaCrypt.bigint("862718293348820473429344482784628181556388621521298319395315527974912"),
rsaCrypt.bigint("1725436586697640946858688965569256363112777243042596638790631055949824"),
rsaCrypt.bigint("3450873173395281893717377931138512726225554486085193277581262111899648"),
rsaCrypt.bigint("6901746346790563787434755862277025452451108972170386555162524223799296"),
rsaCrypt.bigint("13803492693581127574869511724554050904902217944340773110325048447598592"),
rsaCrypt.bigint("27606985387162255149739023449108101809804435888681546220650096895197184"),
rsaCrypt.bigint("55213970774324510299478046898216203619608871777363092441300193790394368"),
rsaCrypt.bigint("110427941548649020598956093796432407239217743554726184882600387580788736"),
rsaCrypt.bigint("220855883097298041197912187592864814478435487109452369765200775161577472"),
rsaCrypt.bigint("441711766194596082395824375185729628956870974218904739530401550323154944"),
rsaCrypt.bigint("883423532389192164791648750371459257913741948437809479060803100646309888"),
rsaCrypt.bigint("1766847064778384329583297500742918515827483896875618958121606201292619776"),
rsaCrypt.bigint("3533694129556768659166595001485837031654967793751237916243212402585239552"),
rsaCrypt.bigint("7067388259113537318333190002971674063309935587502475832486424805170479104"),
rsaCrypt.bigint("14134776518227074636666380005943348126619871175004951664972849610340958208"),
rsaCrypt.bigint("28269553036454149273332760011886696253239742350009903329945699220681916416"),
rsaCrypt.bigint("56539106072908298546665520023773392506479484700019806659891398441363832832"),
rsaCrypt.bigint("113078212145816597093331040047546785012958969400039613319782796882727665664"),
rsaCrypt.bigint("226156424291633194186662080095093570025917938800079226639565593765455331328"),
rsaCrypt.bigint("452312848583266388373324160190187140051835877600158453279131187530910662656"),
rsaCrypt.bigint("904625697166532776746648320380374280103671755200316906558262375061821325312"),
rsaCrypt.bigint("1809251394333065553493296640760748560207343510400633813116524750123642650624"),
rsaCrypt.bigint("3618502788666131106986593281521497120414687020801267626233049500247285301248"),
rsaCrypt.bigint("7237005577332262213973186563042994240829374041602535252466099000494570602496"),
rsaCrypt.bigint("14474011154664524427946373126085988481658748083205070504932198000989141204992"),
rsaCrypt.bigint("28948022309329048855892746252171976963317496166410141009864396001978282409984"),
rsaCrypt.bigint("57896044618658097711785492504343953926634992332820282019728792003956564819968"),
rsaCrypt.bigint("115792089237316195423570985008687907853269984665640564039457584007913129639936"),
}

rsaCrypt.powersTwo[0] = rsaCrypt.bigint("1")

rsaCrypt.bigZero = rsaCrypt.bigint(0)
rsaCrypt.bigOne = rsaCrypt.bigint(1)

rsaCrypt.numberToBytes = function (num, bits, byteSize)
	if bits > #rsaCrypt.powersTwo then
		error("Too many bits. Must be <= " .. #rsaCrypt.powersTwo .. ".")
	end

	num = rsaCrypt.bigint(num)

	local resultBits = {}
	resultBits[1] = {}
	for i = bits - 1, 0, -1 do
		local expVal = rsaCrypt.powersTwo[i]
		local resultant = num - expVal
		if expVal <= resultant then
			-- Invalid data!
			return nil
		end

		if resultant < rsaCrypt.bigZero then
			-- A zero bit
			if #(resultBits[#resultBits]) >= byteSize then
				table.insert(resultBits, {0})
			else
				table.insert(resultBits[#resultBits], 0)
			end
		else
			-- A one bit
			num = resultant
			if #(resultBits[#resultBits]) >= byteSize then
				table.insert(resultBits, {1})
			else
				table.insert(resultBits[#resultBits], 1)
			end
		end

		if num == rsaCrypt.bigint(0) then
			break
		end
	end

	local results = {}
	for _, binarySeq in pairs(resultBits) do
		local thisResult = 0
		for k, bin in pairs(binarySeq) do
			if bin == 1 then
				thisResult = thisResult + 2^(byteSize - k)
			end
		end
		table.insert(results, thisResult)
	end

	return results
end

rsaCrypt.bytesToNumber = function (bytes, bits, byteSize)
	if bits > #rsaCrypt.powersTwo then
		error("Too many bits. Must be <= " .. #rsaCrypt.powersTwo .. ".")
	end

	if #bytes > bits/byteSize then
		error("Too many bytes to store into the number of bits available. Must be <= " ..
			bits/byteSize .. ".")
	end

	local binary = {}
	for _, byte in pairs(bytes) do
		for i = byteSize - 1, 0, -1 do
			if byte - (2 ^ i) < 0 then
				table.insert(binary, 0)
			else
				table.insert(binary, 1)
				byte = byte - (2 ^ i)
			end
		end
	end

	local num = rsaCrypt.bigint(0)
	for i = 1, #binary do
		if binary[i] == 1 then
			num = num + rsaCrypt.powersTwo[bits - i]
		end
	end

	return tostring(num)
end

rsaCrypt.encodeBigNumbers = function (numbers)
	for k, v in pairs(numbers) do
		numbers[k] = tostring(v)
	end
	return numbers
end

rsaCrypt.stringToBytes = function (str)
	local result = {}
	for i = 1, #str do
		table.insert(result, string.byte(str, i))
	end
	return result
end

rsaCrypt.bytesToString = function (bytes)
	local str = ""
	for _, v in pairs(bytes) do
		str = str .. string.char(v)
	end
	return str
end

rsaCrypt.modexp = function (base, exponent, modulus)
	local r = 1

	while true do
		if exponent % 2 == rsaCrypt.bigOne then
			r = r * base % modulus
		end
		exponent = exponent / 2

		if exponent == rsaCrypt.bigZero then
			break
		end
		base = base * base % modulus
	end

	return r
end

rsaCrypt.crypt = function (key, number)
	local exp
	if key.public then
		exp = rsaCrypt.bigint(key.public)
	else
		exp = rsaCrypt.bigint(key.private)
	end

	return tostring(rsaCrypt.modexp(rsaCrypt.bigint(number), exp, rsaCrypt.bigint(key.shared)))
end

--
-- END OF LIBRARY
--


--
-- RSA Key Generator
-- By 1lann
--
-- Refer to license: http://pastebin.com/9gWSyqQt
--

rsaKeygen = {}

--
-- Start of my (1lann's) code
--

rsaKeygen.bigZero = rsaCrypt.bigint(0)
rsaKeygen.bigOne = rsaCrypt.bigint(1)

rsaKeygen.gcd = function (a, b)
	if b ~= rsaKeygen.bigZero then
		return rsaKeygen.gcd(b, a % b)
	else
		return a
	end
end

rsaKeygen.modexp = function (base, exponent, modulus)
	local r = 1

	while true do
		if exponent % 2 == rsaKeygen.bigOne then
			r = r * base % modulus
		end
		exponent = exponent / 2

		if exponent == rsaKeygen.bigZero then
			break
		end
		base = base * base % modulus
	end

	return r
end

rsaKeygen.bigRandomWithLength = function (length, cap)
	if not cap then
		cap = 999999999
	end

	local randomString = tostring(math.random(100000000, cap))

	while true do
		randomString = randomString ..
			tostring(math.random(100000000, cap))
		if #randomString >= length then
			local finalRandom = randomString:sub(1, length)
			if finalRandom:sub(-1, -1) == "2" then
				return rsaCrypt.bigint(finalRandom:sub(1, -2) .. "3")
			elseif finalRandom:sub(-1, -1) == "4" then
				return rsaCrypt.bigint(finalRandom:sub(1, -2) .. "5")
			elseif finalRandom:sub(-1, -1) == "6" then
				return rsaCrypt.bigint(finalRandom:sub(1, -2) .. "7")
			elseif finalRandom:sub(-1, -1) == "8" then
				return rsaCrypt.bigint(finalRandom:sub(1, -2) .. "9")
			elseif finalRandom:sub(-1, -1) == "0" then
				return rsaCrypt.bigint(finalRandom:sub(1, -2) .. "1")
			else
				return rsaCrypt.bigint(finalRandom)
			end
		end
	end
end

rsaKeygen.bigRandom = function (minNum, maxNum)
	if maxNum < rsaCrypt.bigint(1000000000) then
		return rsaCrypt.bigint(math.random(rsaCrypt.biginttonumber(minNum),
			rsaCrypt.biginttonumber(maxNum)))
	end

	local maxString = tostring(maxNum)
	local cap = tonumber(tostring(maxNum):sub(1, 9))
	local range = #maxString - #tostring(minNum)

	if range == 0 then
		return rsaKeygen.bigRandomWithLength(#maxString, cap)
	end

	if #maxString > 30 then
		return rsaKeygen.bigRandomWithLength(#maxString - 1)
	end

	local randomLength = math.random(1, 2^(#maxString - 1))
	for i = 1, #maxString - 1 do
		if randomLength <= (2^i) then
			return rsaKeygen.bigRandomWithLength(i)
		end
	end
end

rsaKeygen.isPrime = function (n)
	if type(n) == "number" then
		n = rsaCrypt.bigint(n)
	end

	if n % 2 == rsaKeygen.bigZero then
		return false
	end

	local s, d = 0, n - rsaKeygen.bigOne
	while d % 2 == rsaKeygen.bigZero do
		s, d = s + 1, d / 2
	end

	for i = 1, 3 do
		local a = rsaKeygen.bigRandom(rsaCrypt.bigint(2), n - 2)
		local x = rsaKeygen.modexp(a, d, n)
		if x ~= rsaKeygen.bigOne and x + 1 ~= n then
			for j = 1, s do
				x = rsaKeygen.modexp(x, rsaCrypt.bigint(2), n)
				if x == rsaKeygen.bigOne then
					return false
				elseif x == n - 1 then
					a = rsaKeygen.bigZero
					break
				end
			end
			if a ~= rsaKeygen.bigZero then
				return false
			end
		end
	end

	return true
end

rsaKeygen.generateLargePrime = function ()
	local i = 0
	while true do
		write(".")
		os.sleep(0.1)
		local randomNumber = rsaKeygen.bigRandomWithLength(39)

		if rsaKeygen.isPrime(randomNumber) then
			return randomNumber
		end
	end
end

rsaKeygen.generatePQ = function (e)
	local randomPrime
	while true do
		randomPrime = rsaKeygen.generateLargePrime()
		if rsaKeygen.gcd(e, randomPrime - 1) == rsaKeygen.bigOne then
			return randomPrime
		end
	end
end

rsaKeygen.euclidean = function (a, b)
	local x, y, u, v = rsaKeygen.bigZero, rsaKeygen.bigOne, rsaKeygen.bigOne, rsaKeygen.bigZero
	while a ~= rsaKeygen.bigZero do
		local q, r = b / a, b % a
		local m, n = x - u * q, y - v * q
		b, a, x, y, u, v = a, r, u, v, m, n
	end
	return b, x, y
end

rsaKeygen.modinv = function (a, m)
	local gcdnum, x, y = rsaKeygen.euclidean(a, m)
	if gcdnum ~= rsaKeygen.bigOne then
		return nil
	else
		return x % m
	end
end

rsaKeygen.generateKeyPair = function ()
	while true do
		local e = rsaKeygen.generateLargePrime()
		write("-")
		sleep(0.1)
		local p = rsaKeygen.generatePQ(e)
		write("-")
		sleep(0.1)
		local q = rsaKeygen.generatePQ(e)
		write("-")
		sleep(0.1)

		local n = p * q
		local phi = (p - 1) * (q - 1)
		local d = rsaKeygen.modinv(e, phi)

		-- 104328 is just a magic number (can be any semi-unique number)
		local encrypted = rsaKeygen.modexp(rsaCrypt.bigint(104328), e, n)
		local decrypted = rsaKeygen.modexp(encrypted, d, n)

		write("+")
		sleep(0.1)
		counter = 0

		if decrypted == rsaCrypt.bigint(104328) then
			counter = 0
			return {
				shared = tostring(n),
				public = tostring(e),
			}, {
				shared = tostring(n),
				private = tostring(d),
			}
		end
	end
end


-- KillaVanilla's RNG('s), composed of the Mersenne Twister RNG and the ISAAC algorithm.

-- Exposed functions:
-- initalize_mt_generator(seed) - Seed the Mersenne Twister RNG.
-- extract_mt() - Get a number from the Mersenne Twister RNG.
-- seed_from_mt(seed) - Seed the ISAAC RNG, optionally seeding the Mersenne Twister RNG beforehand.
-- generate_isaac() - Force a reseed.
-- random(min, max) - Get a random number between min and max.

isaac = {}

-- Helper functions:
isaac.toBinary = function (a) -- Convert from an integer to an arbitrary-length table of bits
	local b = {}
	local copy = a
	while true do
		table.insert(b, copy % 2)
		copy = math.floor(copy / 2)
		if copy == 0 then
			break
		end
	end
	return b
end

isaac.fromBinary = function (a) -- Convert from an arbitrary-length table of bits (from toBinary) to an integer
	local dec = 0
	for i=#a, 1, -1 do
		dec = dec * 2 + a[i]
	end
	return dec
end

-- ISAAC internal state:
isaac.aa = 0
isaac.bb = 0
isaac.cc = 0
isaac.randrsl = {} -- Acts as entropy/seed-in. Fill to randrsl[256].
isaac.mm = {} -- Fill to mm[256]. Acts as output.

-- Mersenne Twister State:
isaac.MT = {} -- Twister state
isaac.index = 0

-- Other variables for the seeding mechanism
isaac.mtSeeded = false
isaac.mtSeed = math.random(1, 2^31-1)

-- The Mersenne Twister can be used as an RNG for non-cryptographic purposes.
-- Here, we're using it to seed the ISAAC algorithm, which *can* be used for cryptographic purposes.

isaac.initalize_mt_generator = function (seed)
	isaac.index = 0
	isaac.MT[0] = seed
	for i=1, 623 do
		local full = ( (1812433253 * bit.bxor(isaac.MT[i-1], bit.brshift(isaac.MT[i-1], 30) ) )+i)
		local b = isaac.toBinary(full)
		while #b > 32 do
			table.remove(b, 1)
		end
		isaac.MT[i] = isaac.fromBinary(b)
	end
end

isaac.generate_mt = function () -- Restock the MT with new random numbers.
	for i=0, 623 do
		local y = bit.band(isaac.MT[i], 0x80000000)
		y = y + bit.band(isaac.MT[(i+1)%624], 0x7FFFFFFF)
		isaac.MT[i] = bit.bxor(isaac.MT[(i+397)%624], bit.brshift(y, 1))
		if y % 2 == 1 then
			isaac.MT[i] = bit.bxor(isaac.MT[i], 0x9908B0DF)
		end
	end
end

isaac.extract_mt = function (min, max) -- Get one number from the Mersenne Twister.
	if isaac.index == 0 then
		isaac.generate_mt()
	end
	local y = isaac.MT[isaac.index]
	min = min or 0
	max = max or 2^32-1
	--print("Accessing: isaac.MT["..isaac.index.."]...")
	y = bit.bxor(y, bit.brshift(y, 11) )
	y = bit.bxor(y, bit.band(bit.blshift(y, 7), 0x9D2C5680) )
	y = bit.bxor(y, bit.band(bit.blshift(y, 15), 0xEFC60000) )
	y = bit.bxor(y, bit.brshift(y, 18) )
	isaac.index = (isaac.index+1) % 624
	return (y % max)+min
end

isaac.seed_from_mt = function (seed) -- seed ISAAC with numbers from the MT:
	if seed then
		isaac.mtSeeded = false
		isaac.mtSeed = seed
	end
	if not isaac.mtSeeded or (math.random(1, 100) == 50) then -- Always seed the first time around. Otherwise, seed approximately once per 100 times.
		isaac.initalize_mt_generator(isaac.mtSeed)
		isaac.mtSeeded = true
		isaac.mtSeed = isaac.extract_mt()
	end
	for i=1, 256 do
		isaac.randrsl[i] = isaac.extract_mt()
	end
end

isaac.mix = function (a,b,c,d,e,f,g,h)
	a = a % (2^32-1)
	b = b % (2^32-1)
	c = c % (2^32-1)
	d = d % (2^32-1)
	e = e % (2^32-1)
	f = f % (2^32-1)
	g = g % (2^32-1)
	h = h % (2^32-1)
	 a = bit.bxor(a, bit.blshift(b, 11))
	 d = (d + a) % (2^32-1)
	 b = (b + c) % (2^32-1)
	 b = bit.bxor(b, bit.brshift(c, 2) )
	 e = (e + b) % (2^32-1)
     c = (c + d) % (2^32-1)
	 c = bit.bxor(c, bit.blshift(d, 8) )
	 f = (f + c) % (2^32-1)
	 d = (d + e) % (2^32-1)
	 d = bit.bxor(d, bit.brshift(e, 16) )
	 g = (g + d) % (2^32-1)
	 e = (e + f) % (2^32-1)
	 e = bit.bxor(e, bit.blshift(f, 10) )
	 h = (h + e) % (2^32-1)
	 f = (f + g) % (2^32-1)
	 f = bit.bxor(f, bit.brshift(g, 4) )
	 a = (a + f) % (2^32-1)
	 g = (g + h) % (2^32-1)
	 g = bit.bxor(g, bit.blshift(h, 8) )
	 b = (b + g) % (2^32-1)
	 h = (h + a) % (2^32-1)
	 h = bit.bxor(h, bit.brshift(a, 9) )
	 c = (c + h) % (2^32-1)
	 a = (a + b) % (2^32-1)
	 return a,b,c,d,e,f,g,h
end

isaac.isaac = function ()
	local x, y = 0, 0
	for i=1, 256 do
		x = isaac.mm[i]
		if (i % 4) == 0 then
			isaac.aa = bit.bxor(isaac.aa, bit.blshift(isaac.aa, 13))
		elseif (i % 4) == 1 then
			isaac.aa = bit.bxor(isaac.aa, bit.brshift(isaac.aa, 6))
		elseif (i % 4) == 2 then
			isaac.aa = bit.bxor(isaac.aa, bit.blshift(isaac.aa, 2))
		elseif (i % 4) == 3 then
			isaac.aa = bit.bxor(isaac.aa, bit.brshift(isaac.aa, 16))
		end
		isaac.aa = (isaac.mm[ ((i+128) % 256)+1 ] + isaac.aa) % (2^32-1)
		y = (isaac.mm[ (bit.brshift(x, 2) % 256)+1 ] + isaac.aa + isaac.bb) % (2^32-1)
		isaac.mm[i] = y
		isaac.bb = (isaac.mm[ (bit.brshift(y,10) % 256)+1 ] + x) % (2^32-1)
		isaac.randrsl[i] = isaac.bb
	end
end

isaac.randinit = function (flag)
	local a,b,c,d,e,f,g,h = 0x9e3779b9,0x9e3779b9,0x9e3779b9,0x9e3779b9,0x9e3779b9,0x9e3779b9,0x9e3779b9,0x9e3779b9-- 0x9e3779b9 is the golden ratio
	isaac.aa = 0
	isaac.bb = 0
	isaac.cc = 0
	for i=1,4 do
		a,b,c,d,e,f,g,h = isaac.mix(a,b,c,d,e,f,g,h)
	end
	for i=1, 256, 8 do
		if flag then
			a = (a + isaac.randrsl[i]) % (2^32-1)
			b = (b + isaac.randrsl[i+1]) % (2^32-1)
			c = (c + isaac.randrsl[i+2]) % (2^32-1)
			d = (b + isaac.randrsl[i+3]) % (2^32-1)
			e = (e + isaac.randrsl[i+4]) % (2^32-1)
			f = (f + isaac.randrsl[i+5]) % (2^32-1)
			g = (g + isaac.randrsl[i+6]) % (2^32-1)
			h = (h + isaac.randrsl[i+7]) % (2^32-1)
		end
		a,b,c,d,e,f,g,h = isaac.mix(a,b,c,d,e,f,g,h)
		isaac.mm[i] = a
		isaac.mm[i+1] = b
		isaac.mm[i+2] = c
		isaac.mm[i+3] = d
		isaac.mm[i+4] = e
		isaac.mm[i+5] = f
		isaac.mm[i+6] = g
		isaac.mm[i+7] = h
	end

	if flag then
		for i=1, 256, 8 do
			a = (a + isaac.randrsl[i]) % (2^32-1)
			b = (b + isaac.randrsl[i+1]) % (2^32-1)
			c = (c + isaac.randrsl[i+2]) % (2^32-1)
			d = (b + isaac.randrsl[i+3]) % (2^32-1)
			e = (e + isaac.randrsl[i+4]) % (2^32-1)
			f = (f + isaac.randrsl[i+5]) % (2^32-1)
			g = (g + isaac.randrsl[i+6]) % (2^32-1)
			h = (h + isaac.randrsl[i+7]) % (2^32-1)
			a,b,c,d,e,f,g,h = isaac.mix(a,b,c,d,e,f,g,h)
			isaac.mm[i] = a
			isaac.mm[i+1] = b
			isaac.mm[i+2] = c
			isaac.mm[i+3] = d
			isaac.mm[i+4] = e
			isaac.mm[i+5] = f
			isaac.mm[i+6] = g
			isaac.mm[i+7] = h
		end
	end
	isaac.isaac()
	randcnt = 256
end

isaac.generate_isaac = function (entropy)
	isaac.aa = 0
	isaac.bb = 0
	isaac.cc = 0
	if entropy and #entropy >= 256 then
		for i=1, 256 do
			isaac.randrsl[i] = entropy[i]
		end
	else
		isaac.seed_from_mt()
	end
	for i=1, 256 do
		isaac.mm[i] = 0
	end
	isaac.randinit(true)
	isaac.isaac()
	isaac.isaac() -- run isaac twice
end

isaac.getRandom = function ()
	if #isaac.mm > 0 then
		return table.remove(isaac.mm, 1)
	else
		isaac.generate_isaac()
		return table.remove(isaac.mm, 1)
	end
end

isaac.random = function (min, max)
	if not max then
		max = 2^32-1
	end
	if not min then
		min = 0
	end
	return (isaac.getRandom() % max) + min
end


-- AES implementation
-- By KillaVanilla

aes = {}

aes.sbox = {
[0]=0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}

aes.inv_sbox = {
[0]=0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}

aes.Rcon = {
[0]=0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d}

-- Finite-field multiplication lookup tables:

aes.mul_2 = {
[0]=0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e,0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e,
0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e,
0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e,0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e,
0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e,0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e,
0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e,0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e,
0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae,0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe,
0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce,0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde,
0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee,0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe,
0x1b,0x19,0x1f,0x1d,0x13,0x11,0x17,0x15,0x0b,0x09,0x0f,0x0d,0x03,0x01,0x07,0x05,
0x3b,0x39,0x3f,0x3d,0x33,0x31,0x37,0x35,0x2b,0x29,0x2f,0x2d,0x23,0x21,0x27,0x25,
0x5b,0x59,0x5f,0x5d,0x53,0x51,0x57,0x55,0x4b,0x49,0x4f,0x4d,0x43,0x41,0x47,0x45,
0x7b,0x79,0x7f,0x7d,0x73,0x71,0x77,0x75,0x6b,0x69,0x6f,0x6d,0x63,0x61,0x67,0x65,
0x9b,0x99,0x9f,0x9d,0x93,0x91,0x97,0x95,0x8b,0x89,0x8f,0x8d,0x83,0x81,0x87,0x85,
0xbb,0xb9,0xbf,0xbd,0xb3,0xb1,0xb7,0xb5,0xab,0xa9,0xaf,0xad,0xa3,0xa1,0xa7,0xa5,
0xdb,0xd9,0xdf,0xdd,0xd3,0xd1,0xd7,0xd5,0xcb,0xc9,0xcf,0xcd,0xc3,0xc1,0xc7,0xc5,
0xfb,0xf9,0xff,0xfd,0xf3,0xf1,0xf7,0xf5,0xeb,0xe9,0xef,0xed,0xe3,0xe1,0xe7,0xe5,
}

aes.mul_3 = {
[0]=0x00,0x03,0x06,0x05,0x0c,0x0f,0x0a,0x09,0x18,0x1b,0x1e,0x1d,0x14,0x17,0x12,0x11,
0x30,0x33,0x36,0x35,0x3c,0x3f,0x3a,0x39,0x28,0x2b,0x2e,0x2d,0x24,0x27,0x22,0x21,
0x60,0x63,0x66,0x65,0x6c,0x6f,0x6a,0x69,0x78,0x7b,0x7e,0x7d,0x74,0x77,0x72,0x71,
0x50,0x53,0x56,0x55,0x5c,0x5f,0x5a,0x59,0x48,0x4b,0x4e,0x4d,0x44,0x47,0x42,0x41,
0xc0,0xc3,0xc6,0xc5,0xcc,0xcf,0xca,0xc9,0xd8,0xdb,0xde,0xdd,0xd4,0xd7,0xd2,0xd1,
0xf0,0xf3,0xf6,0xf5,0xfc,0xff,0xfa,0xf9,0xe8,0xeb,0xee,0xed,0xe4,0xe7,0xe2,0xe1,
0xa0,0xa3,0xa6,0xa5,0xac,0xaf,0xaa,0xa9,0xb8,0xbb,0xbe,0xbd,0xb4,0xb7,0xb2,0xb1,
0x90,0x93,0x96,0x95,0x9c,0x9f,0x9a,0x99,0x88,0x8b,0x8e,0x8d,0x84,0x87,0x82,0x81,
0x9b,0x98,0x9d,0x9e,0x97,0x94,0x91,0x92,0x83,0x80,0x85,0x86,0x8f,0x8c,0x89,0x8a,
0xab,0xa8,0xad,0xae,0xa7,0xa4,0xa1,0xa2,0xb3,0xb0,0xb5,0xb6,0xbf,0xbc,0xb9,0xba,
0xfb,0xf8,0xfd,0xfe,0xf7,0xf4,0xf1,0xf2,0xe3,0xe0,0xe5,0xe6,0xef,0xec,0xe9,0xea,
0xcb,0xc8,0xcd,0xce,0xc7,0xc4,0xc1,0xc2,0xd3,0xd0,0xd5,0xd6,0xdf,0xdc,0xd9,0xda,
0x5b,0x58,0x5d,0x5e,0x57,0x54,0x51,0x52,0x43,0x40,0x45,0x46,0x4f,0x4c,0x49,0x4a,
0x6b,0x68,0x6d,0x6e,0x67,0x64,0x61,0x62,0x73,0x70,0x75,0x76,0x7f,0x7c,0x79,0x7a,
0x3b,0x38,0x3d,0x3e,0x37,0x34,0x31,0x32,0x23,0x20,0x25,0x26,0x2f,0x2c,0x29,0x2a,
0x0b,0x08,0x0d,0x0e,0x07,0x04,0x01,0x02,0x13,0x10,0x15,0x16,0x1f,0x1c,0x19,0x1a,
}

aes.mul_9 = {
[0]=0x00,0x09,0x12,0x1b,0x24,0x2d,0x36,0x3f,0x48,0x41,0x5a,0x53,0x6c,0x65,0x7e,0x77,
0x90,0x99,0x82,0x8b,0xb4,0xbd,0xa6,0xaf,0xd8,0xd1,0xca,0xc3,0xfc,0xf5,0xee,0xe7,
0x3b,0x32,0x29,0x20,0x1f,0x16,0x0d,0x04,0x73,0x7a,0x61,0x68,0x57,0x5e,0x45,0x4c,
0xab,0xa2,0xb9,0xb0,0x8f,0x86,0x9d,0x94,0xe3,0xea,0xf1,0xf8,0xc7,0xce,0xd5,0xdc,
0x76,0x7f,0x64,0x6d,0x52,0x5b,0x40,0x49,0x3e,0x37,0x2c,0x25,0x1a,0x13,0x08,0x01,
0xe6,0xef,0xf4,0xfd,0xc2,0xcb,0xd0,0xd9,0xae,0xa7,0xbc,0xb5,0x8a,0x83,0x98,0x91,
0x4d,0x44,0x5f,0x56,0x69,0x60,0x7b,0x72,0x05,0x0c,0x17,0x1e,0x21,0x28,0x33,0x3a,
0xdd,0xd4,0xcf,0xc6,0xf9,0xf0,0xeb,0xe2,0x95,0x9c,0x87,0x8e,0xb1,0xb8,0xa3,0xaa,
0xec,0xe5,0xfe,0xf7,0xc8,0xc1,0xda,0xd3,0xa4,0xad,0xb6,0xbf,0x80,0x89,0x92,0x9b,
0x7c,0x75,0x6e,0x67,0x58,0x51,0x4a,0x43,0x34,0x3d,0x26,0x2f,0x10,0x19,0x02,0x0b,
0xd7,0xde,0xc5,0xcc,0xf3,0xfa,0xe1,0xe8,0x9f,0x96,0x8d,0x84,0xbb,0xb2,0xa9,0xa0,
0x47,0x4e,0x55,0x5c,0x63,0x6a,0x71,0x78,0x0f,0x06,0x1d,0x14,0x2b,0x22,0x39,0x30,
0x9a,0x93,0x88,0x81,0xbe,0xb7,0xac,0xa5,0xd2,0xdb,0xc0,0xc9,0xf6,0xff,0xe4,0xed,
0x0a,0x03,0x18,0x11,0x2e,0x27,0x3c,0x35,0x42,0x4b,0x50,0x59,0x66,0x6f,0x74,0x7d,
0xa1,0xa8,0xb3,0xba,0x85,0x8c,0x97,0x9e,0xe9,0xe0,0xfb,0xf2,0xcd,0xc4,0xdf,0xd6,
0x31,0x38,0x23,0x2a,0x15,0x1c,0x07,0x0e,0x79,0x70,0x6b,0x62,0x5d,0x54,0x4f,0x46,
}

aes.mul_11 = {
[0]=0x00,0x0b,0x16,0x1d,0x2c,0x27,0x3a,0x31,0x58,0x53,0x4e,0x45,0x74,0x7f,0x62,0x69,
0xb0,0xbb,0xa6,0xad,0x9c,0x97,0x8a,0x81,0xe8,0xe3,0xfe,0xf5,0xc4,0xcf,0xd2,0xd9,
0x7b,0x70,0x6d,0x66,0x57,0x5c,0x41,0x4a,0x23,0x28,0x35,0x3e,0x0f,0x04,0x19,0x12,
0xcb,0xc0,0xdd,0xd6,0xe7,0xec,0xf1,0xfa,0x93,0x98,0x85,0x8e,0xbf,0xb4,0xa9,0xa2,
0xf6,0xfd,0xe0,0xeb,0xda,0xd1,0xcc,0xc7,0xae,0xa5,0xb8,0xb3,0x82,0x89,0x94,0x9f,
0x46,0x4d,0x50,0x5b,0x6a,0x61,0x7c,0x77,0x1e,0x15,0x08,0x03,0x32,0x39,0x24,0x2f,
0x8d,0x86,0x9b,0x90,0xa1,0xaa,0xb7,0xbc,0xd5,0xde,0xc3,0xc8,0xf9,0xf2,0xef,0xe4,
0x3d,0x36,0x2b,0x20,0x11,0x1a,0x07,0x0c,0x65,0x6e,0x73,0x78,0x49,0x42,0x5f,0x54,
0xf7,0xfc,0xe1,0xea,0xdb,0xd0,0xcd,0xc6,0xaf,0xa4,0xb9,0xb2,0x83,0x88,0x95,0x9e,
0x47,0x4c,0x51,0x5a,0x6b,0x60,0x7d,0x76,0x1f,0x14,0x09,0x02,0x33,0x38,0x25,0x2e,
0x8c,0x87,0x9a,0x91,0xa0,0xab,0xb6,0xbd,0xd4,0xdf,0xc2,0xc9,0xf8,0xf3,0xee,0xe5,
0x3c,0x37,0x2a,0x21,0x10,0x1b,0x06,0x0d,0x64,0x6f,0x72,0x79,0x48,0x43,0x5e,0x55,
0x01,0x0a,0x17,0x1c,0x2d,0x26,0x3b,0x30,0x59,0x52,0x4f,0x44,0x75,0x7e,0x63,0x68,
0xb1,0xba,0xa7,0xac,0x9d,0x96,0x8b,0x80,0xe9,0xe2,0xff,0xf4,0xc5,0xce,0xd3,0xd8,
0x7a,0x71,0x6c,0x67,0x56,0x5d,0x40,0x4b,0x22,0x29,0x34,0x3f,0x0e,0x05,0x18,0x13,
0xca,0xc1,0xdc,0xd7,0xe6,0xed,0xf0,0xfb,0x92,0x99,0x84,0x8f,0xbe,0xb5,0xa8,0xa3,
}

aes.mul_13 = {
[0]=0x00,0x0d,0x1a,0x17,0x34,0x39,0x2e,0x23,0x68,0x65,0x72,0x7f,0x5c,0x51,0x46,0x4b,
0xd0,0xdd,0xca,0xc7,0xe4,0xe9,0xfe,0xf3,0xb8,0xb5,0xa2,0xaf,0x8c,0x81,0x96,0x9b,
0xbb,0xb6,0xa1,0xac,0x8f,0x82,0x95,0x98,0xd3,0xde,0xc9,0xc4,0xe7,0xea,0xfd,0xf0,
0x6b,0x66,0x71,0x7c,0x5f,0x52,0x45,0x48,0x03,0x0e,0x19,0x14,0x37,0x3a,0x2d,0x20,
0x6d,0x60,0x77,0x7a,0x59,0x54,0x43,0x4e,0x05,0x08,0x1f,0x12,0x31,0x3c,0x2b,0x26,
0xbd,0xb0,0xa7,0xaa,0x89,0x84,0x93,0x9e,0xd5,0xd8,0xcf,0xc2,0xe1,0xec,0xfb,0xf6,
0xd6,0xdb,0xcc,0xc1,0xe2,0xef,0xf8,0xf5,0xbe,0xb3,0xa4,0xa9,0x8a,0x87,0x90,0x9d,
0x06,0x0b,0x1c,0x11,0x32,0x3f,0x28,0x25,0x6e,0x63,0x74,0x79,0x5a,0x57,0x40,0x4d,
0xda,0xd7,0xc0,0xcd,0xee,0xe3,0xf4,0xf9,0xb2,0xbf,0xa8,0xa5,0x86,0x8b,0x9c,0x91,
0x0a,0x07,0x10,0x1d,0x3e,0x33,0x24,0x29,0x62,0x6f,0x78,0x75,0x56,0x5b,0x4c,0x41,
0x61,0x6c,0x7b,0x76,0x55,0x58,0x4f,0x42,0x09,0x04,0x13,0x1e,0x3d,0x30,0x27,0x2a,
0xb1,0xbc,0xab,0xa6,0x85,0x88,0x9f,0x92,0xd9,0xd4,0xc3,0xce,0xed,0xe0,0xf7,0xfa,
0xb7,0xba,0xad,0xa0,0x83,0x8e,0x99,0x94,0xdf,0xd2,0xc5,0xc8,0xeb,0xe6,0xf1,0xfc,
0x67,0x6a,0x7d,0x70,0x53,0x5e,0x49,0x44,0x0f,0x02,0x15,0x18,0x3b,0x36,0x21,0x2c,
0x0c,0x01,0x16,0x1b,0x38,0x35,0x22,0x2f,0x64,0x69,0x7e,0x73,0x50,0x5d,0x4a,0x47,
0xdc,0xd1,0xc6,0xcb,0xe8,0xe5,0xf2,0xff,0xb4,0xb9,0xae,0xa3,0x80,0x8d,0x9a,0x97,
}

aes.mul_14 = {
[0]=0x00,0x0e,0x1c,0x12,0x38,0x36,0x24,0x2a,0x70,0x7e,0x6c,0x62,0x48,0x46,0x54,0x5a,
0xe0,0xee,0xfc,0xf2,0xd8,0xd6,0xc4,0xca,0x90,0x9e,0x8c,0x82,0xa8,0xa6,0xb4,0xba,
0xdb,0xd5,0xc7,0xc9,0xe3,0xed,0xff,0xf1,0xab,0xa5,0xb7,0xb9,0x93,0x9d,0x8f,0x81,
0x3b,0x35,0x27,0x29,0x03,0x0d,0x1f,0x11,0x4b,0x45,0x57,0x59,0x73,0x7d,0x6f,0x61,
0xad,0xa3,0xb1,0xbf,0x95,0x9b,0x89,0x87,0xdd,0xd3,0xc1,0xcf,0xe5,0xeb,0xf9,0xf7,
0x4d,0x43,0x51,0x5f,0x75,0x7b,0x69,0x67,0x3d,0x33,0x21,0x2f,0x05,0x0b,0x19,0x17,
0x76,0x78,0x6a,0x64,0x4e,0x40,0x52,0x5c,0x06,0x08,0x1a,0x14,0x3e,0x30,0x22,0x2c,
0x96,0x98,0x8a,0x84,0xae,0xa0,0xb2,0xbc,0xe6,0xe8,0xfa,0xf4,0xde,0xd0,0xc2,0xcc,
0x41,0x4f,0x5d,0x53,0x79,0x77,0x65,0x6b,0x31,0x3f,0x2d,0x23,0x09,0x07,0x15,0x1b,
0xa1,0xaf,0xbd,0xb3,0x99,0x97,0x85,0x8b,0xd1,0xdf,0xcd,0xc3,0xe9,0xe7,0xf5,0xfb,
0x9a,0x94,0x86,0x88,0xa2,0xac,0xbe,0xb0,0xea,0xe4,0xf6,0xf8,0xd2,0xdc,0xce,0xc0,
0x7a,0x74,0x66,0x68,0x42,0x4c,0x5e,0x50,0x0a,0x04,0x16,0x18,0x32,0x3c,0x2e,0x20,
0xec,0xe2,0xf0,0xfe,0xd4,0xda,0xc8,0xc6,0x9c,0x92,0x80,0x8e,0xa4,0xaa,0xb8,0xb6,
0x0c,0x02,0x10,0x1e,0x34,0x3a,0x28,0x26,0x7c,0x72,0x60,0x6e,0x44,0x4a,0x58,0x56,
0x37,0x39,0x2b,0x25,0x0f,0x01,0x13,0x1d,0x47,0x49,0x5b,0x55,0x7f,0x71,0x63,0x6d,
0xd7,0xd9,0xcb,0xc5,0xef,0xe1,0xf3,0xfd,0xa7,0xa9,0xbb,0xb5,0x9f,0x91,0x83,0x8d,
}

aes.bxor = bit.bxor
aes.insert = table.insert

aes.copy = function (input)
	local c = {}
	for i, v in pairs(input) do
		c[i] = v
	end
	return c
end

aes.subBytes = function (input, invert)
	for i=1, #input do
		if not (aes.sbox[input[i]] and aes.inv_sbox[input[i]]) then
			error("subBytes: input["..i.."] > 0xFF")
		end
		if invert then
			input[i] = aes.inv_sbox[input[i]]
		else
			input[i] = aes.sbox[input[i]]
		end
	end
	return input
end

aes.shiftRows = function (input)
	local copy = {}
	-- Row 1: No change
	copy[1] = input[1]
	copy[2] = input[2]
	copy[3] = input[3]
	copy[4] = input[4]
	-- Row 2: Offset 1
	copy[5] = input[6]
	copy[6] = input[7]
	copy[7] = input[8]
	copy[8] = input[5]
	-- Row 3: Offset 2
	copy[9] = input[11]
	copy[10] = input[12]
	copy[11] = input[9]
	copy[12] = input[10]
	-- Row 4: Offset 3
	copy[13] = input[16]
	copy[14] = input[13]
	copy[15] = input[14]
	copy[16] = input[15]
	return copy
end

aes.invShiftRows = function (input)
	local copy = {}
	-- Row 1: No change
	copy[1] = input[1]
	copy[2] = input[2]
	copy[3] = input[3]
	copy[4] = input[4]
	-- Row 2: Offset 1
	copy[5] = input[8]
	copy[6] = input[5]
	copy[7] = input[6]
	copy[8] = input[7]
	-- Row 3: Offset 2
	copy[9] = input[11]
	copy[10] = input[12]
	copy[11] = input[9]
	copy[12] = input[10]
	-- Row 4: Offset 3
	copy[13] = input[14]
	copy[14] = input[15]
	copy[15] = input[16]
	copy[16] = input[13]
	return copy
end

aes.finite_field_mul = function (a,b) -- Multiply two numbers in GF(256), assuming that polynomials are 8 bits wide
	local product = 0
	local mulA, mulB = a,b
	for i=1, 8 do
		--print("FFMul: MulA: "..mulA.." MulB: "..mulB)
		if mulA == 0 or mulB == 0 then
			break
		end
		if bit.band(1, mulB) > 0 then
			product = aes.bxor(product, mulA)
		end
		mulB = bit.brshift(mulB, 1)
		local carry = bit.band(0x80, mulA)
		mulA = bit.band(0xFF, bit.blshift(mulA, 1))
		if carry > 0 then
			mulA = aes.bxor( mulA, 0x1B )
		end
	end
	return product
end

aes.mixColumn = function (column)
	local output = {}
	--print("MixColumn: #column: "..#column)
	output[1] = aes.bxor( aes.mul_2[column[1]], aes.bxor( aes.mul_3[column[2]], aes.bxor( column[3], column[4] ) ) )
	output[2] = aes.bxor( column[1], aes.bxor( aes.mul_2[column[2]], aes.bxor( aes.mul_3[column[3]], column[4] ) ) )
	output[3] = aes.bxor( column[1], aes.bxor( column[2], aes.bxor( aes.mul_2[column[3]], aes.mul_3[column[4]] ) ) )
	output[4] = aes.bxor( aes.mul_3[column[1]], aes.bxor( column[2], aes.bxor( column[3], aes.mul_2[column[4]] ) ) )
	return output
end

aes.invMixColumn = function (column)
	local output = {}
	--print("InvMixColumn: #column: "..#column)
	output[1] = aes.bxor( aes.mul_14[column[1]], aes.bxor( aes.mul_11[column[2]], aes.bxor( aes.mul_13[column[3]], aes.mul_9[column[4]] ) ) )
	output[2] = aes.bxor( aes.mul_9[column[1]], aes.bxor( aes.mul_14[column[2]], aes.bxor( aes.mul_11[column[3]], aes.mul_13[column[4]] ) ) )
	output[3] = aes.bxor( aes.mul_13[column[1]], aes.bxor( aes.mul_9[column[2]], aes.bxor( aes.mul_14[column[3]], aes.mul_11[column[4]] ) ) )
	output[4] = aes.bxor( aes.mul_11[column[1]], aes.bxor( aes.mul_13[column[2]], aes.bxor( aes.mul_9[column[3]], aes.mul_14[column[4]] ) ) )
	return output
end

aes.mixColumns = function (input, invert)
	--print("MixColumns: #input: "..#input)
	-- Ooops. I mixed the ROWS instead of the COLUMNS on accident.
	local output = {}
	--[[
	local c1 = { input[1], input[2], input[3], input[4] }
	local c2 = { input[5], input[6], input[7], input[8] }
	local c3 = { input[9], input[10], input[11], input[12] }
	local c4 = { input[13], input[14], input[15], input[16] }
	]]
	local c1 = { input[1], input[5], input[9], input[13] }
	local c2 = { input[2], input[6], input[10], input[14] }
	local c3 = { input[3], input[7], input[11], input[15] }
	local c4 = { input[4], input[8], input[12], input[16] }
	if invert then
		c1 = aes.invMixColumn(c1)
		c2 = aes.invMixColumn(c2)
		c3 = aes.invMixColumn(c3)
		c4 = aes.invMixColumn(c4)
	else
		c1 = aes.mixColumn(c1)
		c2 = aes.mixColumn(c2)
		c3 = aes.mixColumn(c3)
		c4 = aes.mixColumn(c4)
	end
	--[[
	output[1] = c1[1]
	output[2] = c1[2]
	output[3] = c1[3]
	output[4] = c1[4]

	output[5] = c2[1]
	output[6] = c2[2]
	output[7] = c2[3]
	output[8] = c2[4]

	output[9] = c3[1]
	output[10] = c3[2]
	output[11] = c3[3]
	output[12] = c3[4]

	output[13] = c4[1]
	output[14] = c4[2]
	output[15] = c4[3]
	output[16] = c4[4]
	]]

	output[1] = c1[1]
	output[5] = c1[2]
	output[9] = c1[3]
	output[13] = c1[4]

	output[2] = c2[1]
	output[6] = c2[2]
	output[10] = c2[3]
	output[14] = c2[4]

	output[3] = c3[1]
	output[7] = c3[2]
	output[11] = c3[3]
	output[15] = c3[4]

	output[4] = c4[1]
	output[8] = c4[2]
	output[12] = c4[3]
	output[16] = c4[4]

	return output
end

aes.addRoundKey = function (input, exp_key, round)
	local output = {}
	for i=1, 16 do
		assert(input[i], "input["..i.."]=nil!")
		assert(exp_key[ ((round-1)*16)+i ], "round_key["..(((round-1)*16)+i).."]=nil!")
		output[i] = aes.bxor( input[i], exp_key[ ((round-1)*16)+i ] )
	end
	return output
end

aes.key_schedule = function (enc_key)
	local function core(in1, in2, in3, in4, i)
		local s1 = in2
		local s2 = in3
		local s3 = in4
		local s4 = in1
		s1 = aes.bxor(aes.sbox[s1], aes.Rcon[i])
		s2 = aes.sbox[s2]
		s3 = aes.sbox[s3]
		s4 = aes.sbox[s4]
		return s1, s2, s3, s4
	end

	local n, b, key_type = 0, 0, 0

	-- Len | n | b |
	-- 128 |16 |176|
	-- 192 |24 |208|
	-- 256 |32 |240|

	-- Determine keysize:

	if #enc_key < 16 then
		error("Encryption key is too small; key size must be more than 16 bytes.")
	elseif #enc_key >= 16 and #enc_key < 24 then
		n = 16
		b = 176
		--key_type = 1
	elseif #enc_key >= 24 and #enc_key < 32 then
		n = 24
		b = 208
		--key_type = 2
	else
		n = 32
		b = 240
		--key_type = 3
	end

	local exp_key = {}
	local rcon_iter = 1
	for i=1, n do
		exp_key[i] = enc_key[i]
	end
	while #exp_key < b do
		local t1 = exp_key[#exp_key]
		local t2 = exp_key[#exp_key-1]
		local t3 = exp_key[#exp_key-2]
		local t4 = exp_key[#exp_key-3]
		t1, t2, t3, t4 = core(t1, t2, t3, t4, rcon_iter)
		rcon_iter = rcon_iter+1
		t1 = aes.bxor(t1, exp_key[#exp_key-(n-1)])
		t2 = aes.bxor(t2, exp_key[#exp_key-(n-2)])
		t3 = aes.bxor(t3, exp_key[#exp_key-(n-3)])
		t4 = aes.bxor(t4, exp_key[#exp_key-(n-4)])
		aes.insert(exp_key, t1)
		aes.insert(exp_key, t2)
		aes.insert(exp_key, t3)
		aes.insert(exp_key, t4)
		for i=1, 3 do
			t1 = aes.bxor(exp_key[#exp_key], exp_key[#exp_key-(n-1)])
			t2 = aes.bxor(exp_key[#exp_key-1], exp_key[#exp_key-(n-2)])
			t3 = aes.bxor(exp_key[#exp_key-2], exp_key[#exp_key-(n-3)])
			t4 = aes.bxor(exp_key[#exp_key-3], exp_key[#exp_key-(n-4)])
			aes.insert(exp_key, t1)
			aes.insert(exp_key, t2)
			aes.insert(exp_key, t3)
			aes.insert(exp_key, t4)
		end
		if key_type == 3 then -- If we're processing a 256 bit key...
			-- Take the previous 4 bytes of the expanded key, run them through the sbox,
			-- then XOR them with the previous n bytes of the expanded key, then output them
			-- as the next 4 bytes of expanded key.
			t1 = aes.bxor(aes.sbox[exp_key[#exp_key]], exp_key[#exp_key-(n-1)])
			t2 = aes.bxor(aes.sbox[exp_key[#exp_key-1]], exp_key[#exp_key-(n-2)])
			t3 = aes.bxor(aes.sbox[exp_key[#exp_key-2]], exp_key[#exp_key-(n-3)])
			t4 = aes.bxor(aes.sbox[exp_key[#exp_key-3]], exp_key[#exp_key-(n-4)])
			aes.insert(exp_key, t1)
			aes.insert(exp_key, t2)
			aes.insert(exp_key, t3)
			aes.insert(exp_key, t4)
		end
		if key_type == 2 or key_type == 3 then -- If we're processing a 192-bit or 256-bit key..
			local i = 2
			if key_type == 3 then
				i = 3
			end
			for j=1, i do
				t1 = aes.bxor(exp_key[#exp_key], exp_key[#exp_key-(n-1)])
				t2 = aes.bxor(exp_key[#exp_key-1], exp_key[#exp_key-(n-2)])
				t3 = aes.bxor(exp_key[#exp_key-2], exp_key[#exp_key-(n-3)])
				t4 = aes.bxor(exp_key[#exp_key-3], exp_key[#exp_key-(n-4)])
				aes.insert(exp_key, t1)
				aes.insert(exp_key, t2)
				aes.insert(exp_key, t3)
				aes.insert(exp_key, t4)
			end
		end
	end
	return exp_key
end

-- Transform a string of bytes into 16 byte blocks, adding padding to ensure that each block contains 16 bytes.
-- For example:
-- "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" (contains 28 0xFF bytes)
-- Is transformed into this:
-- {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}, {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0,0,0,0} (16 0xFF bytes, followed by 12 0xFF bytes and 4 0x00 bytes for padding)

aes.breakIntoBlocks = function (data)
	if type(data) ~= "string" then
		error("breakIntoBlocks: data is not a string", 2)
	end
	while (#data % 16) ~= 0 do
		data = data.."\0"
	end
	local blocks = {}
	local blockNum = 1
	local output = {}
	for i=1, #data, 16 do
		blocks[blockNum] = {}
		for j=1, 16 do
			blocks[blockNum][j] = string.byte(data, ((blockNum-1)*16)+j, ((blockNum-1)*16)+j)
		end
		blockNum = blockNum+1
	end
	return blocks
end

-- Transform a string into a series of blocks.

-- For example, to get a key from a string:
-- local key = strToBlocks(keyStr)
-- key = key[1]

aes.strToBlocks = function (str)
	local rawBytestream = {}
	local blocks = {}
	for i=1, #str do
		rawBytestream[i] = string.byte(str, i, i)
	end
	for i=1, math.ceil(#rawBytestream / 16) do
		blocks[i] = {}
		for j=1, 16 do
			blocks[i][j] = rawBytestream[ ((i-1)*16)+j ] or 0
		end
	end
	return blocks
end

-- Encrypt / Decrypt individual blocks:

aes.encrypt_block = function (data, key)
	local exp_key = aes.key_schedule(key)
	local state = data
	local nr = 0

	if #exp_key == 176 then -- Key type 1 (128-bits)
		nr = 10
	elseif #exp_key == 208 then -- Key type 2 (192-bits)
		nr = 12
	elseif #exp_key == 240 then -- Key type 3 (256-bits)
		nr = 14
	else
		error("encrypt_block: Unknown key size?", 2)
	end

	-- Inital round:
	state = aes.addRoundKey(state, exp_key, 1)

	-- Repeat (Nr-1) times:
	for round_num = 2, nr-1 do
		state = aes.subBytes(state)
		state = aes.shiftRows(state)
		state = aes.mixColumns(state)
		state = aes.addRoundKey(state, exp_key, round_num)
	end

	-- Final round (No mixColumns()):
	state = aes.subBytes(state)
	state = aes.shiftRows(state)
	state = aes.addRoundKey(state, exp_key, nr)
	return state
end

aes.decrypt_block = function (data, key)
	local exp_key = aes.key_schedule(key)
	local state = data
	local nr = 0

	if #exp_key == 176 then -- Key type 1 (128-bits)
		nr = 10
	elseif #exp_key == 208 then -- Key type 2 (192-bits)
		nr = 12
	elseif #exp_key == 240 then -- Key type 3 (256-bits)
		nr = 14
	else
		error("decrypt_block: Unknown key size?", 2)
	end

	-- Inital round:
	state = aes.addRoundKey(state, exp_key, nr)

	-- Repeat (Nr-1) times:
	for round_num = nr-1, 2, -1 do
		state = aes.invShiftRows(state)
		state = aes.subBytes(state, true)
		state = aes.addRoundKey(state, exp_key, round_num)
		state = aes.mixColumns(state, true)
	end

	-- Final round (No mixColumns()):
	state = aes.invShiftRows(state)
	state = aes.subBytes(state, true)
	state = aes.addRoundKey(state, exp_key, 1)
	return state
end

aes.encrypt_block_customExpKey = function (data, exp_key--[[, key_type]]) -- Encrypt blocks, but using a precalculated expanded key instead of performing the key expansion on every step like with the normal encrypt_block(2) call
	local state = data
	local nr = 0
	if #exp_key == 176 then -- Key type 1 (128-bits)
		nr = 10
	elseif #exp_key == 208 then -- Key type 2 (192-bits)
		nr = 12
	elseif #exp_key == 240 then -- Key type 3 (256-bits)
		nr = 14
	else
		error("encrypt_block: Unknown key size?", 2)
	end

	-- Inital round:
	state = aes.addRoundKey(state, exp_key, 1)

	-- Repeat (Nr-1) times:
	for round_num = 2, nr-1 do
		state = aes.subBytes(state)
		state = aes.shiftRows(state)
		state = aes.mixColumns(state)
		state = aes.addRoundKey(state, exp_key, round_num)
	end

	-- Final round (No mixColumns()):
	state = aes.subBytes(state)
	state = aes.shiftRows(state)
	state = aes.addRoundKey(state, exp_key, nr)
	return state
end

aes.decrypt_block_customExpKey = function (data, exp_key--[[, key_type]])
	local state = data
	local nr = 0
	if #exp_key == 176 then -- Key type 1 (128-bits)
		nr = 10
	elseif #exp_key == 208 then -- Key type 2 (192-bits)
		nr = 12
	elseif #exp_key == 240 then -- Key type 3 (256-bits)
		nr = 14
	else
		error("decrypt_block: Unknown key size?", 2)
	end

	-- Inital round:
	state = aes.addRoundKey(state, exp_key, nr)

	-- Repeat (Nr-1) times:
	for round_num = nr-1, 2, -1 do
		state = aes.invShiftRows(state)
		state = aes.subBytes(state, true)
		state = aes.addRoundKey(state, exp_key, round_num)
		state = aes.mixColumns(state, true)
	end

	-- Final round (No mixColumns()):
	state = aes.invShiftRows(state)
	state = aes.subBytes(state, true)
	state = aes.addRoundKey(state, exp_key, 1)
	return state
end

-- Encrypt / Decrypt bytestreams (tables of bytes):

-- ECB (electronic codebook) Mode (not secure, do not use):

aes.encrypt_bytestream_ecb = function (data, key)
	local blocks = {}
	local outputBytestream = {}
	local exp_key = aes.key_schedule(key)
	for i=1, #data, 16 do
		local block = {}
		for j=1, 16 do
			block[j] = data[i+(j-1)] or 0
		end
		block = aes.encrypt_block_customExpKey(block, exp_key)
		for j=1, 16 do
			table.insert(outputBytestream, block[j])
		end
		os.queueEvent("")
		os.pullEvent("")
	end
	return outputBytestream
end

aes.decrypt_bytestream_ecb = function (data, key)
	local outputBytestream = {}
	local exp_key = aes.key_schedule(key)
	for i=1, #data, 16 do
		local block = {}
		for j=1, 16 do
			block[j] = data[i+(j-1)] or 0
		end
		block = aes.decrypt_block_customExpKey(block, exp_key)
		for j=1, 16 do
			table.insert(outputBytestream, block[j])
		end
		os.queueEvent("")
		os.pullEvent("")
	end
	for i=#outputBytestream, 1, -1 do
		if outputBytestream[i] ~= 0 then
			break
		else
			outputBytestream[i] = nil
		end
	end
	return outputBytestream
end

-- CBC (cipher-block chaining) mode:

aes.encrypt_bytestream = function (data, key, init_vector)
	local blocks = { init_vector }
	local outputBytestream = {}
	local exp_key = aes.key_schedule(key)
	if not init_vector then
		error("encrypt_bytestream: No initalization vector was passed.", 2)
	end
	for i=1, #data do
		if data[i] == nil or data[i] >= 256 then
			if type(data[i]) == "number" then
				error("encrypt_bytestream: Invalid data at i="..i.." data[i]="..data[i], 2)
			else
				error("encrypt_bytestream: Invalid data at i="..i.." data[i]="..type(data[i]), 2)
			end
		end
	end
	local s = os.clock()
	for i=1, math.ceil(#data/16) do
		local block = {}
		if not blocks[i] then
			error("encrypt_bytestream: blocks["..i.."] is nil! Input size: "..#data, 2)
		end
		for j=1, 16 do
			block[j] = data[((i-1)*16)+j] or 0
			block[j] = aes.bxor(block[j], blocks[i][j]) -- XOR this block with the previous one
		end
		--print("#bytes: "..#block)
		block = aes.encrypt_block_customExpKey(block, exp_key)
		table.insert(blocks, block)
		for j=1, 16 do
			aes.insert(outputBytestream, block[j])
		end
        if os.clock() - s >= 2.5 then
            os.queueEvent("")
            os.pullEvent("")
            s = os.clock()
        end
	end
	return outputBytestream
end

aes.decrypt_bytestream = function (data, key, init_vector)
	local blocks = { init_vector }
	local outputBytestream = {}
	local exp_key = aes.key_schedule(key)
	if not init_vector then
		error("decrypt_bytestream: No initalization vector was passed.", 2)
	end
	local s = os.clock()
	for i=1, math.ceil(#data/16) do
		local block = {}
		if not blocks[i] then
			error("decrypt_bytestream: blocks["..i.."] is nil! Input size: "..#data, 2)
		end
		for j=1, 16 do
			block[j] = data[((i-1)*16)+j] or 0
		end
		table.insert(blocks, block)
		local dec_block = aes.decrypt_block_customExpKey(block, exp_key)
		for j=1, 16 do
			dec_block[j] = aes.bxor(dec_block[j], blocks[i][j]) -- We use XOR on the plaintext, not the ciphertext
			table.insert(outputBytestream, dec_block[j])
		end
        if os.clock() - s >= 2.5 then
            os.queueEvent("")
            os.pullEvent("")
            s = os.clock()
        end
	end
	-- Remove padding:
	for i=#outputBytestream, #outputBytestream-15, -1 do
		if outputBytestream[i] ~= 0 then
			break
		else
			outputBytestream[i] = nil
		end
	end
	return outputBytestream
end

-- Encrypt / Decrypt strings:

aes.encrypt_str = function (data, key, iv)
	local byteStream = {}
	for i=1, #data do
		table.insert(byteStream, string.byte(data, i, i))
	end
	local output_bytestream = {}
	if iv then
		output_bytestream = aes.encrypt_bytestream(byteStream, key, iv)
	else
		output_bytestream = aes.encrypt_bytestream_ecb(byteStream, key)
	end
	local output = ""
	for i=1, #output_bytestream do
		output = output..string.char(output_bytestream[i])
	end
	return output
end

aes.decrypt_str = function (data, key, iv)
	local byteStream = {}
	for i=1, #data do
		table.insert(byteStream, string.byte(data, i, i))
	end
	local output_bytestream = {}
	if iv then
		output_bytestream = aes.decrypt_bytestream(byteStream, key, iv)
	else
		output_bytestream = aes.decrypt_bytestream_ecb(byteStream, key)
	end
	local output = ""
	for i=1, #output_bytestream do
		output = output..string.char(output_bytestream[i])
	end
	return output
end

aes.davies_meyer = function (data, h0)
	local last_h = h0
    for dm_iter=1, 16 do
        for i=1, math.ceil(#data/16) do
            local block = {}
            for j=1, 16 do
                block[j] = data[((i-1)*16)+j] or 0
            end
            local block = aes.encrypt_block(last_h, block)
            for j=1, 16 do
                block[j] = aes.bxor(block[j], last_h[j]) -- XOR h[i-1] with h[i].
            end
            last_h = block
            os.queueEvent("")
            os.pullEvent("")
        end
    end
	return last_h
end

aes.increment_ctr = function (blk)
	local cpy = {}
	for i=1, 16 do
		cpy[i] = blk[i] or 0
	end
	cpy[1] = cpy[1] + incAmt
	for i=2, 16 do
		if cpy[i-1] <= 255 then
			break
		end
		local carry = cpy[i-1] - 255
		cpy[i] = cpy[i]+carry
	end
	return cpy
end

aes.counter_mode_context = {
	key = {},
	ctr = {},
	stream_cache = {}, -- Use "leftover" bytes from generate() here.
	set_key = function(self, key)
		if type(key) == "string" then
			if #key < 16 then
				error("set_key: Key length ("..#key..") must be at least 16 characters!", 2)
			end
			for i=1, 16 do
				self.key[i] = string.byte(key, i, i)
			end
		elseif type(key) == "table" then
			if #key < 16 then
				error("set_key: Key length ("..#key..") must be at least 16 bytes!", 2)
			end
			for i=1, 16 do
				if type(key[i]) ~= "number" or key[i] > 255 or key[i] < 0 then
					if type(key[i]) == "nil" then
						error("set_key: Value key["..i.."] is invalid: nil", 2)
					else
						error("set_key: Value key["..i.."] is invalid: "..key[i], 2)
					end
				end
				self.key[i] = key[i]
			end
		else
			error("set_key: Key type is not supported: "..type(key), 2)
		end
	end,
	set_ctr = function(self, ctr)
		if type(ctr) == "string" then
			if #ctr < 16 then
				error("set_ctr: Counter length ("..#ctr..") must be at least 16 characters!", 2)
			end
			for i=1, 16 do
				self.ctr[i] = string.byte(ctr, i, i)
			end
		elseif type(ctr) == "table" then
			if #ctr < 16 then
				error("set_ctr: Counter length ("..#ctr..") must be at least 16 bytes!", 2)
			end
			for i=1, 16 do
				if type(ctr[i]) ~= "number" or ctr[i] > 255 or ctr[i] < 0 then
					if type(ctr[i]) == "nil" then
						error("set_ctr: Value ctr["..i.."] is invalid: nil", 2)
					else
						error("set_ctr: Value ctr["..i.."] is invalid: "..ctr[i], 2)
					end
				end
				self.ctr[i] = ctr[i]
			end
		elseif type(ctr) == "number" then
			local b1 = bit.band( ctr, 0xFF )
			local b2 = bit.band( bit.brshift(bit.band( ctr, 0xFF00 ), 8), 0xFF )
			local b3 = bit.band( bit.brshift(bit.band( ctr, 0xFF0000 ), 16), 0xFF )
			local b4 = bit.band( bit.brshift(bit.band( ctr, 0xFF000000 ), 24), 0xFF )
			self.ctr = {}
			for i=1, 16 do
				self.ctr[i] = 0
			end
			self.ctr[1] = b1
			self.ctr[2] = b2
			self.ctr[3] = b3
			self.ctr[4] = b4
		else
			error("set_ctr: Counter type is not supported: "..type(ctr), 2)
		end
	end,
	generate = function(self, bytes)
		local genBytes = {}
		if #self.stream_cache >= bytes then
			for i=1, bytes do
				table.insert(genBytes, table.remove(self.stream_cache))
			end
		else
			for i=1, #self.stream_cache do
				table.insert(genBytes, table.remove(self.stream_cache))
			end
			local blocksToGenerate = math.ceil((bytes - #genBytes) / 16)
			for i=1, blocksToGenerate-1 do
				self.ctr = aes.increment_ctr(self.ctr)
				local block = aes.encrypt_block(self.ctr, self.key)
				for i=1, 16 do
					table.insert(genBytes, block[i])
				end
			end
			self.ctr = aes.increment_ctr(self.ctr)
			local block = aes.encrypt_block(self.ctr, self.key)
			for i=1, (bytes - #genBytes) do
				table.insert(genBytes, table.remove(block))
			end
			for i=1, #block do
				table.insert(self.stream_cache, table.remove(block))
			end
		end
		return genBytes
	end,
}

aes.new_ctrMode = function (key, iv)
	local context = {
		stream_cache = {},
		key = {},
		iv = {},
		__index = aes.counter_mode_context,
	}
	setmetatable(context, context)
	context:set_key(key)
	context:set_ctr(iv)
	return context
end


-- Simple thread API by immibis

threadAPI = {}

threadAPI.threads = {}
threadAPI.starting = {}
threadAPI.eventFilter = nil

rawset(os, "startThread", function(fn, blockTerminate)
	table.insert(threadAPI.starting, {
		cr = coroutine.create(fn),
		blockTerminate = blockTerminate or false,
		error = nil,
		dead = false,
		filter = nil
	})
end)

threadAPI.tick = function (t, evt, ...)
	if t.dead then return end
	if t.filter ~= nil and evt ~= t.filter then return end
	if evt == "terminate" and t.blockTerminate then return end

	coroutine.resume(t.cr, evt, ...)
	t.dead = (coroutine.status(t.cr) == "dead")
end

threadAPI.tickAll = function ()
	if #threadAPI.starting > 0 then
		local clone = threadAPI.starting
		threadAPI.starting = {}
		for _,v in ipairs(clone) do
			threadAPI.tick(v)
			table.insert(threadAPI.threads, v)
		end
	end
	local e
	if threadAPI.eventFilter then
		e = {threadAPI.eventFilter(coroutine.yield())}
	else
		e = {coroutine.yield()}
	end
	local dead = nil
	for k,v in ipairs(threadAPI.threads) do
		threadAPI.tick(v, unpack(e))
		if v.dead then
			if dead == nil then dead = {} end
			table.insert(dead, k - #dead)
		end
	end
	if dead ~= nil then
		for _,v in ipairs(dead) do
			table.remove(threadAPI.threads, v)
		end
	end
end

rawset(os, "setGlobalEventFilter", function(fn)
	if threadAPI.eventFilter ~= nil then error("This can only be set once!") end
	threadAPI.eventFilter = fn
	rawset(os, "setGlobalEventFilter", nil)
end)

threadAPI.startThreading = function (mainThread)
 if type(mainThread) == "function" then
 	os.startThread(mainThread)
 else
	 os.startThread(function() shell.run("shell") end)
 end

 while #threadAPI.threads > 0 or #threadAPI.starting > 0 do
 	threadAPI.tickAll()
 end

 print("All threads terminated!")
 print("Exiting thread manager")
end

------- END THIRD PARTY -------

------- BEGIN CRYPTONET -------
-- The following code was written by me (SiliconSloth).


-- Channel used to send discovery requests and responses.
DISCOVERY_CHANNEL = 65531
-- If set to true CryptoNet will also broadcast all messages over the Rednet
-- reapter channel, which allows CryptoNet messages to be repeated by the built-in
-- program repeat. Disabling this is a little more secure as an attacker won't know
-- which channel you are communicating over.
local repeatMessages = true
-- Whether to print log messages or not.
local loggingEnabled = true
-- Directory CryptoNet looks for files in.
local workingDir = ""
-- All servers currently open on this computer.
local allServers = {}
-- All client sockets (opened with connect()) open on this computer.
local allClientSockets = {}


local function log(message)
  if loggingEnabled then
    print("[CryptoNet] "..message)
  end
end


--
-- ACCESSORS
--

function getLoggingEnabled()
  return loggingEnabled
end


function setLoggingEnabled(enabled)
  loggingEnabled = enabled
end


function getRepeatMessages()
  return repeatMessages
end


function setRepeatMessages(repMsgs)
  repeatMessages = repMsgs
end


function getWorkingDirectory()
  return workingDir
end


function setWorkingDirectory(dir)
  if type(dir) ~= "string" then
    error("Directory must be a string.", 2)
  end
  workingDir = dir
end


function getAllServers()
  return allServers
end


function getAllClientSockets()
  return allClientSockets
end


--
-- VALIDITY CHECKS
--

-- Check that the key is a 16 element table of numbers.
function keyValid(key)
	if not (type(key) == "table" and #key == 16) then
		return false
	end
	-- Make sure all elements are numbers.
	for _,v in pairs(key) do
		if type(v) ~= "number" then
			return false
		end
	end
	return true
end


-- Check that a table has all the parts required to be a valid private key.
function privateKeyValid(key)
  return type(key) == "table" and type(key.private) == "string" and type(key.shared) == "string"
end


-- Check that a table has all the parts required to be a valid public key.
function publicKeyValid(key)
  return type(key) == "table" and type(key.public) == "string" and type(key.shared) == "string"
end


-- Check that a table has all the parts required to be a valid server certificate.
-- If ignoreKey is true it is acceptable for a server to have no key,
-- but if present it must be valid.
-- The signature is always optional but must be valid (syntactically,
-- it isn't actually verified here) if present.
function certificateValid(certificate, ignoreKey)
	-- All certificates must contain the server name.
  if type(certificate) ~= "table" or type(certificate.name) ~= "string" then
    return false
  end

	-- A certificate must contain the server's public key, unless ignoreKey is true.
  if certificate.key == nil and not ignoreKey then
    return false
  end
	-- Ensure that the public key is valid, if present.
  if certificate.key ~= nil and not publicKeyValid(certificate.key) then
    return false
  end

	-- A certificate should only have a signature if it also contains a key.
  if certificate.key == nil and certificate.signature ~= nil then
    return false
  end
	-- If a signature is present (which it doesn't need to be), it must be a string.
  if certificate.signature ~= nil and type(certificate.signature) ~= "string" then
    return false
  end

  return true
end


-- Check that a table has everything it needs to be a valid server.
function serverValid(server)
  return type(server) == "table"
     and type(server.name) == "string"
     and certificateValid(server.certificate)
     and privateKeyValid(server.privateKey)
     and type(server.modemSide) == "string"
     and type(server.channel) == "number"
     and type(server.userTable) == "table"
     and type(server.userTablePath) == "string"
     and type(server.sockets) == "table"
end


-- Check that a table has everything it needs to be a valid socket.
function socketValid(socket)
  return type(socket) == "table"
     and type(socket.sender) == "string"
     and type(socket.target) == "string"
     and keyValid(socket.key)
     and type(socket.modemSide) == "string"
     and type(socket.channel) == "number"
     and type(socket.permissionLevel) == "number"
     and type(socket.receivedMessages) == "table"
end


-- Check that all the entries in a user table are valid.
function userTableValid(userTable)
  if type(userTable) ~= "table" then
    return false
  end
  for username,entry in pairs(userTable) do
    if type(username) ~= "string" or type(entry[1]) ~= "table" or type(entry[2]) ~= "number" then
      return false
    end
  end
  return true
end


--
-- HELPERS
--

-- Used to process modem side arguments passed to functions.
function resolveModemSide(modemSide)
	-- If no modem side argument is provided, search for a modem and use that side.
  if modemSide == nil then
    for _,side in pairs(peripheral.getNames()) do
      if peripheral.getType(side) == "modem" then
        modemSide = side
        break
      end
    end
    if modemSide == nil then
      error("Could not find a modem.", 3)
    end
  else
		-- If an argument was provided, check that it is a valid side.
    local found = false
    for _,side in pairs(redstone.getSides()) do
      if side == modemSide then
        found = true
        break
      end
    end
    if not found then
      error(tostring(modemSide).." is not a valid side.", 3)
    end
  end
  if peripheral.getType(modemSide) ~= "modem" then
    error("No modem on side "..modemSide..".", 3)
  end

  log("Using modem "..modemSide..".")
  return modemSide
end


-- Decides which channel a server should communicate on, based on its name.
-- This function will always return the same channel for a given server name,
-- allowing clients to find out the channel of a server without any prior
-- communications with it.
function getChannel(serverName)
  local nameHash = sha256.digest(serverName)
	-- Use the first two bytes of the hash as the channel number, so that the full range
	-- of acceptable channels can be used.
  local channel = nameHash[1] + nameHash[2]*2^8
	-- Avoid clashing with the lower channels, which are likely being used by
	-- standard Rednet users.
  if channel < 100 then
    channel = channel + 100
	-- Reserve the highest channels for Rednet and CryptoNet's internal use.
  elseif channel > 65530 then
    channel = channel - 5
  end

  return channel
end


-- Check if any servers or sockets on this machine are using the specified channel
-- on the specified modem.
function channelInUse(channel, modemSide)
	-- Check the client sockets.
	for _,socket in pairs(allClientSockets) do
		if socket.channel == channel and socket.modemSide == modemSide then
			return true
		end
	end
	-- Check the server channels.
	for _,server in pairs(allServers) do
		if server.channel == channel and server.modemSide == modemSide then
			return true
		end
	end

	return false
end


-- Convert a table of bytes into a string.
local function bytesToString(bytes)
  local str = ""
  for _,byte in pairs(bytes) do
    local ok, char = pcall(string.char, byte)
		-- If there are invalid bytes in the string, return nil without raising an error.
		-- This is to prevent attackers from crashing the system by sending invalid characters
		-- in encrypted messages.
    if not ok then
      return nil
    end
    str = str..char
  end
  return str
end


-- Serialize pretty much any Lua data type as a string so that it can be encrypted
-- and sent over CryptoNet.  The resulting string starts with a characer
-- identifying the type of the data, followed by a string representation of the data.
local function serializeAny(value)
  if type(value) == "nil" then
    return "x"
  elseif type(value) == "boolean" then
    return value and "b1" or "b0"
  elseif type(value) == "number" then
    return "n"..tostring(value)
  elseif type(value) == "string" then
    return "s"..value
  elseif type(value) == "table" then
    return "t"..textutils.serialize(value)
  else
    error("Can't serialize "..type(value).."s.", 2)
  end
end


-- Deserialize data serialized by serializeAny.
local function deserializeAny(str)
  local typeChar = str:sub(1,1)
  local valueStr = str:sub(2)
  if typeChar == "x" then
    return nil
  elseif typeChar == "b" then
    return valueStr == "1"
  elseif typeChar == "n" then
    return tonumber(valueStr)
  elseif typeChar == "s" then
    return valueStr
  elseif typeChar == "t" then
    return textutils.unserialize(valueStr)
  else
    error("Invalid type character: "..typeChar, 2)
  end
end


-- Serialize a certificate or RSA key into a string, for saving to a file.
-- The textutils functions don't seem to like the huge strings of numbers in
-- the keys, so quotation marks must be added to them before serialization,
-- which is what this function does.
function serializeCertOrKey(obj)
  if type(obj) ~= "table" then
    error("Can only serialize tables.", 2)
  end
	-- Add the certificate name, if it exists.
  local output = {name=obj.name}

	-- If this is a key, add its number string parts with quotes around them
	-- to keep textutils happy.
  if type(obj.public) == "string" then
    output.public = "\""..obj.public.."\""
  end
  if type(obj.private) == "string" then
    output.private = "\""..obj.private.."\""
  end
  if type(obj.shared) == "string" then
    output.shared = "\""..obj.shared.."\""
  end

	-- If this is a certificate with a key, do the above for the key.
  if type(obj.key) == "table" then
    output.key = {}
    if type(obj.key.public) == "string" then
      output.key.public = "\""..obj.key.public.."\""
    end
    if type(obj.key.private) == "string" then
      output.key.private = "\""..obj.key.private.."\""
    end
    if type(obj.key.shared) == "string" then
      output.key.shared = "\""..obj.key.shared.."\""
    end
  end

	-- If the certificate has a signature, that must have quotes as well.
  if type(obj.signature) == "string" then
    output.signature = "\""..obj.signature.."\""
  end

	-- Serialize the table as normal.
  return textutils.serialize(output)
end


-- Deserialize certificates or RSA keys serialized by serializeCertOrKey().
-- This involves deserializing as normal and removing the quotation marks added
-- during serialization.
function deserializeCertOrKey(str)
  if str == nil then return nil end
	-- Deserialize as normal.
  local output = textutils.unserialize(str)
  if type(output) ~= "table" then
    return output
  end

	-- If this is a key, remove the quotes from the number string parts.
  if type(output.public) == "string" then
    output.public = string.gsub(output.public, "\"", "")
  end
  if type(output.private) == "string" then
    output.private = string.gsub(output.private, "\"", "")
  end
  if type(output.shared) == "string" then
    output.shared = string.gsub(output.shared, "\"", "")
  end

	-- If this is a certificate with a key, do the above for the key.
  if output.key ~= nil then
    if type(output.key.public) == "string" then
      output.key.public = string.gsub(output.key.public, "\"", "")
    end
    if type(output.key.private) == "string" then
      output.key.private = string.gsub(output.key.private, "\"", "")
    end
    if type(output.key.shared) == "string" then
      output.key.shared = string.gsub(output.key.shared, "\"", "")
    end
  end

  if type(output.signature) == "string" then
    output.signature = string.gsub(output.signature, "\"", "")
  end

  return output
end


-- Generate random 16 byte sequence that can be used as a key or
-- initialization vector for AES encryption.
function generateKey()
	local iv = {}
	-- Convert four 4-byte integers into 16 bytes.
	for j=1,4 do
		local num = isaac.random()
		for i=0,3 do
			-- Extract 8 bits at a time, by shifting right and applying a mask.
			table.insert(iv, bit.band(bit.brshift(num, 8*i), 2^8-1))
		end
	end
	return iv
end


-- Generate an unsigned certificate and corresponding private key for a server
-- with the given name. The certificate is distributed to clients, who can use
-- the public key it contains to encrypt messages using RSA such that only
-- this server can read them, using the private key.
function generateCertificate(name)
  log("Generating keys... (may take some time)")
  publicKey, privateKey = rsaKeygen.generateKeyPair()
  print("")
  log("Done!")
	-- The certificate contains the name and public key of the server.
  return {name=name, key=publicKey}, privateKey
end


-- Load a certificate authority public key from the specified file and validate it,
-- or just validate the key itself if passed directly as the argument.
-- If key is left nil, a default filename of "certAuth.key" is used.
--
-- key (string or key table, default: "certAuth.key"):
--   The file to load the key from, or the key itself to validate.
--
-- Returns the loaded key, or nil if not found or invalid.
function loadCertAuthKey(key)
  if key == nil then
		-- Default value.
    key = "certAuth.key"
  end
	-- If key is a file path...
  if type(key) == "string" then
    local keyFilename = key
		-- Make paths relative to the current CryptoNet working directory.
    local keyPath = workingDir == "" and keyFilename or workingDir.."/"..keyFilename
    log("Checking "..keyPath.." for cert auth key...")
    if fs.isDir(keyPath) or not fs.exists(keyPath) then
			if fs.isDir(keyPath) then
      	log(keyFilename.." is not a file, will not be able to verify signatures.")
			else
      	log(keyFilename.." does not exist, will not be able to verify signatures.")
			end
      return nil
    else
      local file = fs.open(keyPath, "r")
      key = deserializeCertOrKey(file.readAll())
      file.close()

      if not publicKeyValid(key) then
        log(keyFilename.." does not contain a valid cert auth key, will not be able to verify signatures.")
        return nil
      else
        log("Loaded cert auth key from "..keyFilename..".")
        return key
      end
    end
	-- If the argument is not a string it should be the key table itself,
	-- so just validate it and return unchanged if valid.
  elseif publicKeyValid(key) then
    return key
  else
    log("Invalid cert auth key, won't be able to verify signatures.")
    return nil
  end
end


-- Verify that the signature on a certificate is valid, using the public key
-- of the trusted certificate authority.
function verifyCertificate(certificate, key)
	-- Signatures are made by encrypting the certificate's hash using the cert auth's private key.
	-- If the signature was generated by the certificate authority that uses the provided public key,
	-- decrypting the signature with this key should yield the certificate's hash.

	-- Find the hash of the certificate.
  local hash = sha256.digest(certificate.name..certificate.key.public..certificate.key.shared)
	-- Decrypt the signature using the provided public key.
  local sigHash = rsaCrypt.bytesToString(rsaCrypt.numberToBytes(rsaCrypt.crypt(key, certificate.signature), 32*8, 8))
	-- See whether the decrypted signature matches the expected hash.
  return tostring(hash) == sigHash
end


--
-- SEND FUNCTIONS
--

-- Send an unencrypted message in the Rednet format using the cryptoNet protocol.
-- CryptoNet uses this internally for sending various message types.
-- If enabled, this function will also send every message it sends on the Rednet
-- repeat channel, allowing the Rednet repeat command to repeat CryptoNet messages.
-- Since these messages are in the format Rednet uses, CryptoNet should be fully
-- compatible with any networking systems designed for Rednet.
local function sendInternal(modemSide, channel, target, message, msgType, sender)
	-- Generate the message in exactly the same format as Rednet.
  local nMessageID = math.random(1, 2147483647)
  local tMessage = {
    nMessageID = nMessageID,
    nRecipient = channel,
    message = {message=message, msgType=msgType, target=target, sender=sender},
    sProtocol = "cryptoNet",
  }

  local modem = peripheral.wrap(modemSide)
  modem.transmit(channel, channel, tMessage)
	-- Allow Rednet repeaters to repeat the message if enabled.
  if repeatMessages then
    modem.transmit(rednet.CHANNEL_REPEAT, channel, tMessage)
  end
end


-- Send an encrypted internal message. Unlike the user-facing send() function,
-- this one only allows strings to be sent.
local function sendEncryptedInternal(socket, message)
  if type(message) ~= "string" then
    error("Message must be a string.", 2)
  end
  if not socketValid(socket) then
    error("Invalid socket.", 2)
  end
	-- Use unique IVs for every message.
	local iv = generateKey()
  local ok, encrypted = pcall(aes.encrypt_str, message, socket.key, iv)
  if ok then
		-- Send the encrypted message and the IVs used to generate it.
		-- We have to send the encrypted string as a table of bytes, because some of
		-- the special characters in the string seem to get lost in transmission otherwise.
    sendInternal(socket.modemSide, socket.channel, socket.target, {{string.byte(encrypted, 1, encrypted:len())}, iv}, "encrypted_message", socket.sender)
  else
    error("Encryption failed: "..encrypted:sub(8), 2)
  end
end


-- Send an encrypted message over the given socket. The message can be pretty much
-- any Lua data type.
function send(socket, message)
  if not socketValid(socket) then
    error("Invalid socket.", 2)
  end
	-- Convert the message to a string before sending, so it can be encrypted.
	-- It will be deserialized at the other end.
  sendEncryptedInternal(socket, serializeAny(message))
end


-- Send an unencrypted message over CryptoNet. Useful for streams of high speed,
-- non-sensitive data. Unencrypted messages have no security features applied,
-- so can be easily exploited by attackers. Only use for non-critical messages.
function sendUnencrypted(socket, message)
  if not socketValid(socket) then
    error("Invalid socket.", 2)
  end
	-- Just send the message as-is.
	sendInternal(socket.modemSide, socket.channel, socket.target, message, "plain_message", socket.sender)
end


--
-- LOGIN SYSTEM
--

-- Hash a password using the username and server name as a salt.
-- Used to secure passwords before they are sent over CryptoNet to a server.
-- Technically this is unnecessary as the connection is encrypted anyway,
-- but it means that even if this is somehow compromised (e.g. with a spoof attack)
-- the attacker won't know the actual password and be able to use it on the user's
-- other accounts, if they use the same password for multiple things.
function hashPassword(username, password, serverName)
  if type(username) ~= "string" then
    error("Username must be a string.", 2)
  end
  if type(password) ~= "string" then
    error("Password must be a string.", 2)
  end
  if type(serverName) ~= "string" then
    error("Server name must be a string.", 2)
  end

  return tostring(sha256.digest(serverName..username..password))
end


-- Load the user table stored at the given path, defaulting to an empty table
-- if the file does not exist.
function loadUserTable(path)
  if type(path) ~= "string" then
    error("Path must be a string.", 2)
  end
  if not fs.exists(path) then
    log(path.." does not exist, creating empty user table.")
    return {}
  end
  if fs.isDir(path) then
    error(path.." is not a file, could not load user table.", 2)
  end

  local file = fs.open(path, "r")
  local userTable = textutils.unserialize(file.readAll())
  file.close()

  if not userTableValid(userTable) then
    error(path.." does not contain a valid user table, user table could not be loaded.", 2)
  end

  log("Loaded user table from "..path..".")
  return userTable
end


-- Save the given user table to the given file.
function saveUserTable(userTable, path)
  if type(path) ~= "string" then
    error("Path must be a string.", 2)
  end
  if not userTableValid(userTable) then
    error("Not a valid user table", 2)
  end

  if fs.isDir(path) then
    error(path.." already exists and is a directory.", 2)
  end

  local file = fs.open(path, "w")
  file.write(textutils.serialize(userTable))
  file.close()
  log("Saved user table to "..path..".")
end


-- Add a user to the given server with the provided details.
-- The provided password should already have been hashed by hashPassword().
-- Default permission level is 1. If there is only one server running,
-- that server will be used by default.
function addUserHashed(username, passHash, permissionLevel, server)
  if type(username) ~= "string" then
    error("Username must be a string.", 2)
  end
  if type(passHash) ~= "string" then
    error("Password hash must be a string.", 2)
  end
  if permissionLevel == nil then
    permissionLevel = 1
  elseif type(permissionLevel) ~= "number" then
    error("Permission level must be a number", 2)
  end

	-- If there is exactly one server running, default to it.
  if server == nil then
    if #allServers == 0 then
      error("No servers running.", 2)
    elseif #allServers == 1 then
      server = allServers[1]
    else
      error("Please specify a server.", 2)
    end
  elseif not serverValid(server) then
    error("Invalid server.", 2)
  end

  if server.userTable[username] ~= nil then
    error("User "..username.." already exists.", 2)
  end

	-- The password is hashed again before going in the database, so that even if
	-- an attacker has access to this file they do not have the original password
	-- required to log into the server from the outside.
	-- PBKDF2 is used over the standard SHA256 digest as it is theoretically harder
	-- to crack.
  server.userTable[username] = {sha256.pbkdf2(passHash, server.name..username, 8), permissionLevel}
  log("Added user "..username..".")
  saveUserTable(server.userTable, server.userTablePath)
end


-- Add a user to the given (local) server's user table with the provided details.
-- The user table is saved to disk, so is non volatile.
-- The server parameter can be left blank if exactly one server is running.
function addUser(username, password, permissionLevel, server)
  if type(username) ~= "string" then
    error("Username must be a string.", 2)
  end
  if type(password) ~= "string" then
    error("Password must be a string.", 2)
  end
  if permissionLevel == nil then
    permissionLevel = 1
  elseif type(permissionLevel) ~= "number" then
    error("Permission level must be a number", 2)
  end

	-- If there is exactly one server running, default to it.
  if server == nil then
    if #allServers == 0 then
      error("No servers running.", 2)
    elseif #allServers == 1 then
      server = allServers[1]
    else
      error("Please specify a server.", 2)
    end
  elseif not serverValid(server) then
    error("Invalid server.", 2)
  end

  if server.userTable[username] ~= nil then
    error("User "..username.." already exists.", 2)
  end

	-- When users log into the server remotely their passwords will be hashed
	-- before being sent, so we must perform the same process here before
	-- adding it to the table.
  addUserHashed(username, hashPassword(username, password, server.name), permissionLevel, server)
end


-- Remove a user from a server.
-- The server parameter can be left blank if exactly one server is running.
function deleteUser(username, server)
  if type(username) ~= "string" then
    error("Username must be a string.", 2)
  end

	-- If there is exactly one server running, default to it.
  if server == nil then
    if #allServers == 0 then
      error("No servers running.", 2)
    elseif #allServers == 1 then
      server = allServers[1]
    else
      error("Please specify a server.", 2)
    end
  elseif not serverValid(server) then
    error("Invalid server.", 2)
  end

  if server.userTable[username] == nil then
    error("No user called "..username..".", 2)
  else
    server.userTable[username] = nil
    log("Deleted user "..username..".")
    saveUserTable(server.userTable, server.userTablePath)
  end
end


-- Check if a user exists on the server.
-- The server parameter can be left blank if exactly one server is running.
function userExists(username, server)
  if type(username) ~= "string" then
    error("Username must be a string.", 2)
  end

	-- If there is exactly one server running, default to it.
  if server == nil then
    if #allServers == 0 then
      error("No servers running.", 2)
    elseif #allServers == 1 then
      server = allServers[1]
    else
      error("Please specify a server.", 2)
    end
  elseif not serverValid(server) then
    error("Invalid server.", 2)
  end

  return server.userTable[username] ~= nil
end


-- Get the hashed password of a user from the users table.
-- The original password cannot be (easily) retrieved from this hash.
-- Returns nil if the user does not exist.
-- The server parameter can be left blank if exactly one server is running.
function getPasswordHash(username, server)
  if type(username) ~= "string" then
    error("Username must be a string.", 2)
  end

	-- If there is exactly one server running, default to it.
  if server == nil then
    if #allServers == 0 then
      error("No servers running.", 2)
    elseif #allServers == 1 then
      server = allServers[1]
    else
      error("Please specify a server.", 2)
    end
  elseif not serverValid(server) then
    error("Invalid server.", 2)
  end

  if server.userTable[username] == nil then
    return nil
  end
  return server.userTable[username][1]
end


-- Get the permission level of a user.
-- Returns nil if the user does not exist.
-- The server parameter can be left blank if exactly one server is running.
function getPermissionLevel(username, server)
  if type(username) ~= "string" then
    error("Username must be a string.", 2)
  end

	-- If there is exactly one server running, default to it.
  if server == nil then
    if #allServers == 0 then
      error("No servers running.", 2)
    elseif #allServers == 1 then
      server = allServers[1]
    else
      error("Please specify a server.", 2)
    end
  elseif not serverValid(server) then
    error("Invalid server.", 2)
  end

  if server.userTable[username] == nil then
    return nil
  end
  return server.userTable[username][2]
end


-- Set the hashed password of a user in the table.
-- Assumes the provided passowrd has already been hashed with hashPassword().
-- The server parameter can be left blank if exactly one server is running.
function setPasswordHashed(username, passHash, server)
  if type(username) ~= "string" then
    error("Username must be a string.", 2)
  end
  if type(passHash) ~= "string" then
    error("Password hash must be a string.", 2)
  end

	-- If there is exactly one server running, default to it.
  if server == nil then
    if #allServers == 0 then
      error("No servers running.", 2)
    elseif #allServers == 1 then
      server = allServers[1]
    else
      error("Please specify a server.", 2)
    end
  elseif not serverValid(server) then
    error("Invalid server.", 2)
  end

  if server.userTable[username] == nil then
    error("No user called "..username..".", 2)
  end

	-- Hash the password again before storing.
  server.userTable[username][1] = sha256.pbkdf2(passHash, server.name..username, 8)
  log("Updated password for "..username..".")
  saveUserTable(server.userTable, server.userTablePath)
end


-- Sets the password of a user in the table.
-- The server parameter can be left blank if exactly one server is running.
function setPassword(username, password, server)
  if type(username) ~= "string" then
    error("Username must be a string.", 2)
  end
  if type(password) ~= "string" then
    error("Password must be a string.", 2)
  end

	-- If there is exactly one server running, default to it.
  if server == nil then
    if #allServers == 0 then
      error("No servers running.", 2)
    elseif #allServers == 1 then
      server = allServers[1]
    else
      error("Please specify a server.", 2)
    end
  elseif not serverValid(server) then
    error("Invalid server.", 2)
  end

  if server.userTable[username] == nil then
    error("No user called "..username..".", 2)
  end

	-- Hash the password before adding, to mimic the hashing performed by clients
	-- logging in remotely.
  setPasswordHashed(username, hashPassword(username, password, server.name), server)
end


-- Set the permission level of a user in the table.
-- The server parameter can be left blank if exactly one server is running.
function setPermissionLevel(username, permissionLevel, server)
  if type(username) ~= "string" then
    error("Username must be a string.", 2)
  end
  if type(permissionLevel) ~= "number" then
    error("Permission level must be a number.", 2)
  end

	-- If there is exactly one server running, default to it.
  if server == nil then
    if #allServers == 0 then
      error("No servers running.", 2)
    elseif #allServers == 1 then
      server = allServers[1]
    else
      error("Please specify a server.", 2)
    end
  elseif not serverValid(server) then
    error("Invalid server.", 2)
  end

  if server.userTable[username] == nil then
    error("No user called "..username..".", 2)
  end

  server.userTable[username][2] = permissionLevel
  log("Updated permission level for "..username..".")
  saveUserTable(server.userTable, server.userTablePath)
end


-- Check that the given password matches the one in the table.
-- Assumes the password has already been hashed by hashPassword().
-- The server parameter can be left blank if exactly one server is running.
function checkPasswordHashed(username, passHash, server)
  if type(username) ~= "string" then
    error("Username must be a string.", 2)
  end
  if type(passHash) ~= "string" then
    error("Password hash must be a string.", 2)
  end

	-- If there is exactly one server running, default to it.
  if server == nil then
    if #allServers == 0 then
      error("No servers running.", 2)
    elseif #allServers == 1 then
      server = allServers[1]
    else
      error("Please specify a server.", 2)
    end
  elseif not serverValid(server) then
    error("Invalid server.", 2)
  end

  if server.userTable[username] == nil then
    return nil
  end

	-- Since we can't unhash the passwords in the table, we must instead
	-- hash the query password and compare it to the hash in the table.
	-- If they are the same, then the original passwords were the same.
  local hash = sha256.pbkdf2(passHash, server.name..username, 8)
	-- Check if all the bytes of the hashes are equal.
  for i=1,#hash do
    if hash[i] ~= server.userTable[username][1][i] then
      return false
    end
  end
  return true
end


-- Check that the given password matches the one in the table.
-- The server parameter can be left blank if exactly one server is running.
function checkPassword(username, password, server)
  if type(username) ~= "string" then
    error("Username must be a string.", 2)
  end
  if type(password) ~= "string" then
    error("Password must be a string.", 2)
  end

	-- If there is exactly one server running, default to it.
  if server == nil then
    if #allServers == 0 then
      error("No servers running.", 2)
    elseif #allServers == 1 then
      server = allServers[1]
    else
      error("Please specify a server.", 2)
    end
  elseif not serverValid(server) then
    error("Invalid server.", 2)
  end

	-- Mimic the client-side hashing before checking.
  return checkPasswordHashed(username, hashPassword(username, password, server.name), server)
end


-- Log into the server connected to this socket, remote or local,
-- with the specified username and password.
-- Assumes the password has already been hashed by hashPassword().
-- If executed on a server socket, the event details of the attempt are returned.
--
-- If successful, the user's details will be stored in the socket.
-- If the socket is already logged in, the username will be overwritten
-- but the permission level will be set to the highest of the old and new one.
-- This allows an admin account to log in then log in as a normal user
-- to temporarily gain elevated privileges as that account.
function loginHashed(socket, username, passHash)
  if not socketValid(socket) then
    error("Invalid socket.", 2)
  end
  if type(username) ~= "string" then
    error("Username must be a string.", 2)
  end
  if type(passHash) ~= "string" then
    error("Password hash must be a string.", 2)
  end

  if socket.server == nil then
		-- If this is a client socket, send a login request to the server.
    sendEncryptedInternal(socket, "lr"..textutils.serialize({username, passHash}))
    log("Sent login request for "..username.." to "..socket.target..".")
  else
		-- If this is a server socket, try to log in as the user
		-- and send the result to the client.
    if socket.server.userTable[username] == nil then
      log("Failed login attempt for "..username..".")
      sendEncryptedInternal(socket, "lf"..username)
      return "login_failed", username, socket, socket.server
    else
      if checkPasswordHashed(username, passHash, socket.server) then
				-- If the password was correct, log the user into the socket.
        socket.username = username
				-- Set the permission level to the greatest of the socket's original
				-- permission level and the new one, so admins can temporarily transfer
				-- their elevated rights to normal accounts.
        socket.permissionLevel = math.max(socket.permissionLevel, getPermissionLevel(username, socket.server))
				-- Tell the client-side socket that the attempt was successful, so it can
				-- change its details as well.
        sendEncryptedInternal(socket, "ls"..textutils.serialize({username, socket.permissionLevel}))
        log(username.." logged in successfully.")
        return "login", username, socket, socket.server
      else
        log("Failed login attempt for "..username..".")
        sendEncryptedInternal(socket, "lf"..username)
        return "login_failed", username, socket, socket.server
      end
    end
  end
end


-- Log into the server connected to this socket, remote or local,
-- with the specified username and password.
-- The password will be hashed before sending for extra security.
-- If executed on a server socket, the event details of the attempt are returned.
--
-- If successful, the user's details will be stored in the socket.
-- If the socket is already logged in, the username will be overwritten
-- but the permission level will be set to the highest of the old and new one.
-- This allows an admin account to log in then log in as a normal user
-- to temporarily gain elevated privileges as that account.
function login(socket, username, password)
  if not socketValid(socket) then
    error("Invalid socket.", 2)
  end
  if type(username) ~= "string" then
    error("Username must be a string.", 2)
  end
  if type(password) ~= "string" then
    error("Password must be a string.", 2)
  end

	-- Get the server name based on whether this is a client or server socket.
  local serverName = socket.server == nil and socket.target or socket.sender
	-- Hash the password before sending.
  return loginHashed(socket, username, hashPassword(username, password, serverName))
end


-- Log out of the user account currently logged in on this socket.
-- If executed on a server socket, the event details are returned.
function logout(socket)
  if not socketValid(socket) then
    error("Invalid socket.", 2)
  end

	-- Tell the other end to log out as well.
  sendEncryptedInternal(socket, "lo")
  if socket.server == nil then
		-- If this is a client socket, all we can do is ask the server to log out.
		-- The actual logging out is only performed once a response is received
		-- from the server.
    log("Sent logout request to "..socket.target..".")
  else
		-- If this is a server socket, we can actually logout.
    local username = socket.username
    socket.username = nil
    socket.permissionLevel = 0

    if username == nil then
      log("Already logged out.")
    else
      log(username.." logged out.")
    end
    return "logout", username, socket, server
  end
end


--
-- CORE NETWORKING
--

-- Check if a Rednet-format message is a CryptoNet one, and return its contents
-- if so. If it is invalid or has been processed before nil is returned.
local function extractMessage(message, receivedIDs)
	-- Check the list of alrady received message IDs to see if any of them are
	-- more than 5 seconds old and can be deleted. The purpose of this list is
	-- to avoid processing messages processed by Rednet's repeat program
	-- more than once, but repeat is unlikely to take 5 seconds to repeat a message.
	-- Since the message IDs are randomly generated, it is good to remove them
	-- from the list as soon as possible to reduce the chance of a future message
	-- with same ID from being blocked.
	-- Note that CryptoNet has a seperate more advanced system for preventing
	-- attackers from sending the same encrypted message twice, handled elsewhere.
  local toDelete = {}
  for id, time in pairs(receivedIDs) do
		-- List the ID for deletion if it is more than 5 seconds old.
    if os.clock() - time > 5 then
      table.insert(toDelete, id)
    end
  end
	-- Remove all the deleted IDs.
  for _,id in pairs(toDelete) do
    receivedIDs[id] = nil
  end

	-- Check that the message follows the Rednet format and is using the cryptoNet protocol.
  if type(message) == "table" and message.sProtocol == "cryptoNet" and type(message.message) == "table" and type(message.nMessageID) == "number" then
		-- If this message ID has not been received already recently,
		-- return the message contents.
    if not receivedIDs[message.nMessageID] then
      receivedIDs[message.nMessageID] = os.clock()
      return message.message
    end
		-- Always keep the latest timestamp of the ID.
    receivedIDs[message.nMessageID] = os.clock()
  end
  return
end


-- Create and host a CryptoNet server, which other machines can remotely connect
-- to. This function will load the certificate and private key of the server
-- from the specified files, or generate new ones if no existing files are found.
-- Note that serverName is the only required parameter; all the others have
-- sensible defaults.
--
-- serverName (string, required):
-- 	The name of the server, which clients will use to connect to it.
-- 	Also determines the channel that the server communicates on.
--
-- discoverable (boolean, default: true):
--	Whether this server responds to discover() requests.
--	Disabling this is more secure as it means clients can't connect unless
--	they already know the name of the server.
--
-- hideCertificate (boolean, default: false):
-- 	If true the server will not distribute its certificate to clients,
--  either in discover() or connect() requests, meaning clients can only
--  connect if they have already been given the certificate manually.
--  Useful if you only want certain manually authorised clients to be able to connect.
--
-- modemSide (string, default: a side that has a modem):
-- 	The modem the server should use.
--
-- certificate (table or string, default: "<serverName>.crt"):
-- 	The certificate of the server. This can either be the certificate table itself,
--	or the name of a file that contains it. If the certicate and key files do not
--  exist, new ones will be generated and saved to the specified files.
--
-- privateKey (table or string, default: "<serverName>_private.key"):
--	The private key of the server. This can either be the key table itself,
--  or the name of a file that contains it. If the certicate and key files do not
--  exist, new ones will be generated and saved to the specified files.
--
-- userTablePath (string, default: "<serverName>_users.tbl"):
--   Path at which to store the user login details table,
--   if/when users are added to the server.
--
-- Returns: The server table, containing the following information:
--	name: The server name
--  certificate: The server's certificate
--  privateKey: The server's private key
--  modemSide: The modem used by the server
--  channel: The channel number the server communicates on
--  hideCertificate: Whether the server distributes its certificate to clients
--  discoverable: Whether the server responds to discover() requests
--  userTable: The table of user login details for the server,
--  		loaded from file or empty by default
--  userTablePath: The name of the user table file
--  sockets: The table of the server's sockets, used to communicate with clients.
--			Starts empty and is populated as clients connect.
function host(serverName, discoverable, hideCertificate, modemSide, certificate, privateKey, userTablePath)
  if type(serverName) ~= "string" then
    error("Server name must be a string.", 2)
  end
	-- Don't allow duplicate server names.
  for _,server in  pairs(allServers) do
    if server.name == serverName then
      error("Server called "..serverName.." already exists.", 2)
    end
  end

  modemSide = resolveModemSide(modemSide)
  local modem = peripheral.wrap(modemSide)

	-- Generate default file names if none were provided, then get the paths
	-- relative to the current working directory.
  local certFilename = type(certificate) == "string" and certificate or serverName..".crt"
  local keyFilename = type(privateKey) == "string" and privateKey or serverName.."_private.key"
  local certificatePath = workingDir == "" and certFilename or workingDir.."/"..certFilename
  local keyPath = workingDir == "" and keyFilename or workingDir.."/"..keyFilename

	-- Now that we've extracted the filenames above, only store the actual certificate
	-- and key in these variables.
  if type(certificate) == "string" then certificate = nil end
  if type(privateKey) == "string" then privateKey = nil end

  if certificate ~= nil and not certificateValid(certificate) then
    error("Invalid certificate.", 2)
  end
  if privateKey ~= nil and not privateKeyValid(privateKey) then
    error("Invalid private key.", 2)
  end

  -- Try loading the certificate from file.
  if certificate == nil then
    log("Checking "..certificatePath.." for certificate...")
    if fs.isDir(certificatePath) then
      error(certFilename.." already exists and is a directory, not a certificate.", 2)
    elseif fs.exists(certificatePath) then
      local file = fs.open(certificatePath, "r")
      certificate = deserializeCertOrKey(file.readAll())
      file.close()

      if not certificateValid(certificate) then
        error(certFilename.." already exists and is not a valid certificate.", 2)
      else
        log("Loaded certificate from "..certFilename..".")
      end
    else
      log("Certificate file not found, will need to generate a new one.")
    end
  end

	-- Try loading the private key from file.
  if privateKey == nil then
    log("Checking "..keyPath.." for private key...")
    if fs.isDir(keyPath) then
      error(keyFilename.." already exists and is a directory, not a keyfile.", 2)
    elseif fs.exists(keyPath) then
      local file = fs.open(keyPath, "r")
      privateKey = deserializeCertOrKey(file.readAll())
      file.close()

      if not privateKeyValid(privateKey) then
        error(keyFilename.." already exists and is not a valid keyfile.", 2)
      else
        log("Loaded private key from "..keyFilename..".")
      end
    else
      log("Private keyfile not found, will need to generate a new one.")
    end
  end

	-- If we have no certificate or private key yet, generate them.
	-- You can't just provide one and not the other, as the public and private
	-- keys must be generated as a pair.
  if certificate == nil and privateKey == nil then
    log("No certificate or private key found, generating new ones.")
    certificate, privateKey = generateCertificate(serverName)

    local file = fs.open(certificatePath, "w")
    file.write(serializeCertOrKey(certificate))
    file.close()
    log("Saved certificate to "..certificatePath..".")

    file = fs.open(keyPath, "w")
    file.write(serializeCertOrKey(privateKey))
    file.close()
    log("Saved private key to "..keyPath..".  Do not share this with anyone!")
  elseif certificate ~= nil and privateKey == nil then
    error("Have a certificate but not a private key, need both or neither.", 2)
  elseif certificate == nil and privateKey ~= nil then
    error("Have a private key but not a certificate, need both or neither.", 2)
  end

	-- It is possible for an attacker to host a server with the same name as yours,
	-- confusing and tricking clients. Having a certifiate authority sign
	-- the certificates of trusted servers prevents this.
  if certificate.signature == nil then
   log("Warning: Your certificate does not have a signature.")
  else
   log("Certificate is signed.")
  end

	-- Open the server's channel (derived from the server name) so it can be used
	-- for communication.
  local channel = getChannel(serverName)
  modem.open(channel)
  log("Hosting on channel "..channel..".")

  if hideCertificate then
    log("Your server is set to require clients to already have its certificate in order to connect to it.")
  end

	-- Allow clients to use discover() to get the name and certificate
	-- of this server without prior knowledge of it.
  if discoverable or discoverable == nil then
    modem.open(DISCOVERY_CHANNEL)
    log("Your server is discoverable.")
  else
    log("Your server is not discoverable.")
  end

	-- Load the server's user table from file, or create a new one if none was found.
  if userTablePath == nil then
    userTablePath = serverName.."_users.tbl"
  end
  local userTable
  if type(userTablePath) == "string" then
		-- Append the current working directory to the table path.
    userTablePath = workingDir == "" and userTablePath or workingDir.."/"..userTablePath
    userTable = loadUserTable(userTablePath)
  else
    error("userTablePath must be a string.", 2)
  end

	-- Create the server table.
  local server = {
    name = serverName,
    certificate = certificate,
    privateKey = privateKey,
    modemSide = modemSide,
    channel = channel,
    hideCertificate = hideCertificate,
    discoverable = discoverable or discoverable == nil,	-- Default to true
    userTable = userTable,
    userTablePath = userTablePath,
    sockets = {}	-- New servers have no connections yet.
  }

  table.insert(allServers, server)
  log("Server ready.")
  return server
end


-- Close a socket or server, such that it will not listen for messages anymore.
-- Closing a server closes all its sockets.
function close(socket)
  if socketValid(socket) then
		-- Let the other end of the socket know it has been closed.
		-- Don't send if this one was closed remotely, since the other end clearly
		-- already knows.
    if not socket.closedRemotely then
      sendEncryptedInternal(socket, "c")
    end
    if socket.server == nil then
			-- If this is a client socket, remove it from the list of client sockets.
			-- This will stop handleModemEvent() from processing messages for it.
      for i=1,#allClientSockets do
        if allClientSockets[i] == socket then
          table.remove(allClientSockets, i)
          break
        end
      end
    else
			-- If this is a server socket, remove it from the server's socket list.
			-- This will stop handleModemEvent() from processing messages for it.
      socket.server.sockets[socket.target] = nil
    end

		-- If this was the only socket communicating on its channel, close the channel
		-- on the modem. Don't close the channel if another socket is still using it.
    if not channelInUse(socket.channel, socket.modemSide) then
      peripheral.wrap(socket.modemSide).close(socket.channel)
      log("Closed socket channel "..socket.channel.." on modem "..socket.modemSide..".")
    end
    log("Closed socket.")

  elseif serverValid(socket) then
		-- If this is a server being closed...
    local server = socket
		-- Create a copy of the server's socket list and close them all.
		-- Closing a socket will remove it from the server's socket list,
		-- so we make a copy so it doesn't change while we're trying to iterate
		-- over it.
    local socketsCopy = {}
    for _,soc in pairs(server.sockets) do
      table.insert(socketsCopy, soc)
    end
    for _,soc in pairs(socketsCopy) do
      close(soc)
    end

		-- Remove the closed server from the server list.
		-- This will stop handleModemEvent() from processing messages for it.
    for i=1,#allServers do
      if allServers[i] == server then
        table.remove(allServers, i)
        break
      end
    end

		-- If this was the only server/socket communicating on its channel, close the channel
		-- on the modem. Don't close the channel if another socket is still using it.
    if not channelInUse(server.channel, server.modemSide) then
      peripheral.wrap(server.modemSide).close(server.channel)
      log("Closed server channel "..server.channel.." on modem "..server.modemSide..".")
    end

		-- If this was the only server using the discovery channel, close it.
    if server.discoverable then
      found = false
      for _,srvr in pairs(allServers) do
        if srvr.discoverable and srvr.modemSide == server.modemSide then
          found = true
          break
        end
      end
      if not found then
        peripheral.wrap(server.modemSide).close(DISCOVERY_CHANNEL)
        log("Closed discovery channel.")
      end
    end
  else
    error("Must be a valid socket or server.", 2)
  end
end


-- Close all sockets and servers on this machine.
function closeAll()
	-- Iteratve backwards so the list isn't chaning in front of us.
  for i=#allClientSockets,1,-1 do
    close(allClientSockets[i])
  end
  for i=#allServers,1,-1 do
    close(allServers[i])
  end
  log("Closed all sockets and servers.")
end


-- Process an encrypted message sent over CryptoNet to a socket,
-- that has already been decrypted.
-- Decrypted messages start with one or two characters that specify the type
-- of the message, which may either be an internal message (e.g. login requests)
-- or an encrypted message sent by a user using the send() function.
--
-- May return the details of a CryptoNet event caused by the message,
-- or nil if none occurs. Also returns a status boolean to say whether the
-- message turned out to have a valid format.
local function handleDecryptedMessage(socket, message)
	local ok = true
	local result = nil
	if message == "c" then
		log("Connection closed by other end.")
		socket.closedRemotely = true
		-- Close our end of the socket too.
		close(socket)
		socket.closedRemotely = nil
		result = {"connection_closed", socket, socket.server}
	elseif message:sub(1,2) == "lr" then
		-- Login requests have the format lr{username,password}
		-- Note that the password will have already been hashed using hashPassword()
		-- by the client before sending.
		local request = textutils.unserialize(message:sub(3))
		if type(request) == "table" and type(request[1]) == "string" and type(request[2]) == "string" then
			result = {loginHashed(socket, request[1], request[2])}
		else
			ok = false
		end
	elseif message:sub(1,2) == "lf" then
		-- Runs on client when server says the login failed. Format: lfusername
		log("Failed login attempt for "..message:sub(3)..".")
		result = {"login_failed", message:sub(3), socket, socket.server}
	elseif message:sub(1,2) == "ls" then
		-- Runs on client when server says the login was successful.
		-- Format: ls{username,permissionLevel}
		local details = textutils.unserialize(message:sub(3))
		if type(details) == "table" and type(details[1]) == "string" and type(details[2]) == "number" then
			socket.username = details[1]
			socket.permissionLevel = details[2]
			log(socket.username.." logged in successfully.")
			result = {"login", socket.username, socket, socket.server}
		else
			-- Response was invalid.
			ok = false
		end
	elseif message == "lo" then
		-- Logout.
		if socket.server == nil then
			-- On client side just reset the user details, the server will already
			-- have logged out its socket.
			local username = socket.username
			socket.username = nil
			socket.permissionLevel = 0

			if username == nil then
				log("Already logged out.")
			else
				log(username.." logged out.")
			end
			result = {"logout", username, socket, nil}
		else
			-- On server side call logout() to also send a message to the client
			-- to tell it to log out.
			result = {logout(socket)}
		end
	else
		-- If the message had none of the above internal message types,
		-- it must be a user-generated encrypted message, which will start with
		-- a data type character. Attempt to deserialize the message as such.
		ok, message = pcall(deserializeAny, message)
		if ok then
			result = {"encrypted_message", message, socket, socket.server}
		end
	end
	return ok, result
end


-- See if the given CryptoNet message is relevant to this server, and act upon
-- it as needed. May return the details of a CryptoNet event caused by the message,
-- or nil if none occurs.
local function handleServerMessage(server, message, messageChannel)
	-- Check if this message is a discovery request,
	-- and respond to it if and only if the server is discoverable.
	if messageChannel == DISCOVERY_CHANNEL and message.msgType == "discovery_request" and server.discoverable then
		-- Remove the public key and signature from the certificate if needed.
		local certificate = server.hideCertificate and {name=server.name} or server.certificate
		sendInternal(server.modemSide, DISCOVERY_CHANNEL, nil, certificate, "discovery_response")
		log("Responded to discovery request.")
	-- If this is a message directed at this server...
	elseif messageChannel == server.channel and message.target == server.name then
		if message.msgType == "certificate_request" and not server.hideCertificate then
			sendInternal(server.modemSide, server.channel, nil, server.certificate, "certificate_response")
			log("Responded to certificate request.")
		elseif message.msgType == "connection_request" and type(message.message) == "string" then
			-- The client will have sent a session key, encryped using the server's public key.
			-- We need to use the private key to decrypt it and use the session key to send
			-- an acknowledgement to the client.
			local encryptedKey = message.message
			if server.sockets[encryptedKey] ~= nil then
				-- This is probably a repeated message, as we have already processed it before.
				log("Received duplicate connection request, ignoring it.")
			else
				-- Try to decrypt the session key using the server's private key.
				local ok, numKey = pcall(rsaCrypt.crypt, server.privateKey, encryptedKey)
				ok, sessKey = pcall(rsaCrypt.numberToBytes, numKey, 16*8, 8)
				-- Validate the key, which should be a table of 16 bytes.
				if ok and (sessKey == nil or #sessKey ~= 16) then
					ok = false
				end
				if not ok then
					log("Received invalid session key.")
				else
					-- Send a message back to the client encrypted with the session key
					-- to prove that we have received it correctly.
					-- The client knows what the message is supposed to be,
					-- allowing it to validate it.
					local response = tostring(sha256.digest(server.name..server.certificate.key.public..server.certificate.key.shared..numKey))
					-- Encrypt the message.
					local iv = generateKey()
					response = aes.encrypt_str(response, sessKey, iv)
					-- From now on the client will be identified by it's encrypted session key.
					sendInternal(server.modemSide, server.channel, encryptedKey, {{string.byte(response, 1, response:len())}, iv}, "connection_response")
					log("Responded to connection request.")

					-- Create the socket object pointing to the client.
					local socket = {sender=server.name, target=encryptedKey, key=sessKey, modemSide=server.modemSide,
													channel=server.channel, server=server, permissionLevel=0, receivedMessages={}}
					server.sockets[encryptedKey] = socket
					return {"connection_opened", socket, server}
				end
			end
		elseif message.msgType == "encrypted_message" and type(message.message) == "table" and #message.message == 2
		 and type(message.message[1]) == "table" and type(message.message[2]) == "table" then
			-- If this is an encrypted message, try decrypting it with the session key
			-- and handle the decrypted message as needed.
			local socket = server.sockets[message.sender]
			local encrypted = bytesToString(message.message[1])
			local iv = message.message[2]
			if socket == nil then
				log("Received a message from a sender who has yet to open a connection.")
			elseif encrypted == nil then
				log("Received invalid message.")
			elseif socket.receivedMessages[encrypted] then
				-- The encryption algorithm adds random numbers to each message before
				-- encrypting it, so even if two messages are identical their encrypted
				-- versions will probably be different. Therefore if we receive the exact
				-- same encrypted message twice it is most likely a malicious duplicate
				-- made by someone without the session key, and so should be ignored.
				log("Received duplicate message, ignoring it.")
			else
				-- Remember we have received this message so we don't accept it again
				-- (see above).
				socket.receivedMessages[encrypted] = true
				local ok, decrypted = pcall(aes.decrypt_str, encrypted, socket.key, iv)
				if ok then
					local ok, result = handleDecryptedMessage(socket, decrypted)
					if ok and result ~= null then
						return result
					end
				end
				if not ok then
					log("Received invalid message.")
				end
			end
		elseif message.msgType == "plain_message" then
			local socket = server.sockets[message.sender]
			if socket ~= nil then
				return {"plain_message", message.message, socket, server}
			else
				log("Received a message from a sender who has yet to open a connection.")
			end
		end
	end
end


-- See if the given CryptoNet message is relevant to this client socket, and act upon
-- it as needed.
--
-- May return the details of a CryptoNet event caused by the message,
-- or nil if none occurs.
local function handleClientMessage(socket, message, messageChannel)
	-- If this is a message directed at this socket...
	if messageChannel == socket.channel and message.sender == socket.target and message.target == socket.sender then
		if message.msgType == "encrypted_message" and type(message.message) == "table" and #message.message == 2
		 and type(message.message[1]) == "table" and type(message.message[2]) == "table" then
			local encrypted = bytesToString(message.message[1])
			local iv = message.message[2]
			if encrypted == nil then
				log("Received invalid message.")
			elseif socket.receivedMessages[encrypted] then
				-- The encryption algorithm adds random numbers to each message before
				-- encrypting it, so even if two messages are identical their encrypted
				-- versions will probably be different. Therefore if we receive the exact
				-- same encrypted message twice it is most likely a malicious duplicate
				-- made by someone without the session key, and so should be ignored.
				log("Received duplicate message, ignoring it.")
			else
				socket.receivedMessages[encrypted] = true
				-- Decrypt the message with the session key and handle as needed.
				local ok, decrypted = pcall(aes.decrypt_str, encrypted, socket.key, iv)
				if ok then
					local ok, result = handleDecryptedMessage(socket, decrypted)
					if ok then
						return result
					end
				end
				if not ok then
					log("Received invalid message.")
				end
			end
		elseif message.msgType == "plain_message" then
			return {"plain_message", message.message, socket, nil}
		end
	end
end


-- Check if the given modem_message event is a CryptoNet message, and if so
-- decrypt and act upon it as needed.
--
-- receivedIDs: A table of recently received message IDs, used to block any
-- 	more messages with the same ID within a cooldown period, on the basis that they
--	are probably the same message repeated.
--
-- May return the details of a CryptoNet event caused by the message,
-- or nil if none occurs.
local function handleModemEvent(event, receivedIDs)
	-- Check if the modem message was a CryptoNet-formatted message, and extract
	-- the message contents.
  local message = extractMessage(event[5], receivedIDs)
  if message ~= nil then
		-- Try passing the message to all servers on this machine.
    for _,server in pairs(allServers) do
			local result = handleServerMessage(server, message, event[3])
			if result ~= nil then
				return result
			end
    end

		-- Try passing the message to all client sockets on this machine.
    for _,socket in pairs(allClientSockets) do
			local result = handleClientMessage(socket, message, event[3])
			if result ~= nil then
				return result
			end
    end
  end

  return nil
end


-- Listens for and handles CryptoNet messages for all sockets and servers
-- on this machine. Returns when a message is received that invokes a
-- user-facing CryptoNet event, with the details of said event.
-- Should ideally be executed inside a while loop alongside event handling logic.
--
-- It is recommended that users use startEventLoop() over a listen() loop,
-- as it creates a new thread for each event received, allowing for calls to sleep()
-- and pullEvent() in event handling code without freezing the rest of the server.
function listen()
	-- Message IDs recently received by this machine that we don't want to
	-- process repeat copies of.
  local receivedIDs = {}
	-- Keep listening for and handling modem_messages until
	-- a CryptoNet event is raised.
  while true do
    local event = {os.pullEvent("modem_message")}
    local newEvent = handleModemEvent(event, receivedIDs)
    if newEvent ~= nil then
      return table.unpack(newEvent)
    end
  end
end


-- Request the certificates of all online CryptoNet servers on the network.
-- Some servers may have been set to not respond to discovery requests,
-- and some will only contain the server name in the certificate, excluding
-- the public key required to connect to the server.
--
-- This function can optionally use a certificate authority public key
-- to verify the signatures of certificates, only returning certificates
-- with valid signatures. By default discover() looks for the public key
-- in "certAuth.key".
--
-- timeout (number, default: 1):
--   The time in seconds to spend listening for responses.
--
-- certAuthKey (table or string, default: "certAuth.key"):
--   The certificate authority public key used to verify signatures,
--   or the path of the file to load it from. If no valid key is found
--   the discovery will still go ahead, but signatures will not be checked.
--
-- allowUnsigned (boolean, default: false):
--   Whether to include certificates with no valid signature in the results.
--   If no valid cert auth key is provided this is ignored, as the certificates
--   cannot be checked without a key.
--
-- modemSide (string, default: a side with a modem):
--   The modem to use to send and receive messages.
--
-- Returns a table of the certificates received, all of which will include
-- the name of server and possibly also the public key and signature.
function discover(timeout, certAuthKey, allowUnsigned, modemSide)
	-- Load and validate the key.
  certAuthKey = loadCertAuthKey(certAuthKey)

  modemSide = resolveModemSide(modemSide)
  local modem = peripheral.wrap(modemSide)
	-- Remember if the modem was already open so we can
	-- close it afterwards if it wasn't.
  local wasOpen = modem.isOpen(DISCOVERY_CHANNEL)
  modem.open(DISCOVERY_CHANNEL)

  log("Discovering...")
  sendInternal(modemSide, DISCOVERY_CHANNEL, nil, nil, "discovery_request")

	-- List of response message IDs we've already received
	-- so we can ignore duplicates.
  local receivedIDs = {}
	-- The received certificates.
  local certificates = {}
	-- Set a timer for when the timeout expires.
  local timer = os.startTimer((type(timeout) == "number") and timeout or 1)
  while true do
		-- Wait for either a modem_message or timer event.
    local event = {os.pullEvent()}
    if event[1] == "modem_message" and event[3] == DISCOVERY_CHANNEL then
			-- See if this is a CryptoNet-formatted message and exract its contents.
      local message = extractMessage(event[5], receivedIDs)
			-- If this is a discovery_response with a correctly formatted certifiate...
      if message ~= nil and message.msgType == "discovery_response" and certificateValid(message.message, true) then
        local certificate = message.message
        local found = false
				-- If we have already received an identical certificate don't add this one.
        for _,cert in pairs(certificates) do
          if certificate.name == cert.name and ((certificate.key == nil and cert.key == nil) or (certificate.key ~= nil and cert.key ~= nil
            and certificate.key.public == cert.key.public and certificate.key.shared == cert.key.shared)) and certificate.signature == cert.signature then
            found = true
            break
          end
        end

        if not found then
          table.insert(certificates, certificate)
        end
      end
    elseif event[1] == "timer" and event[2] == timer then
			-- Stop listening for events once the time is up.
      break
    end
  end

	-- Close the discovery channel if it wasn't open before we started.
  if not wasOpen then
    modem.close(DISCOVERY_CHANNEL)
  end

	-- If we have a valid cert auth key to use,
	-- verify the signatures of the received certificates.
	-- If allowUnsigned is false any certificates without valid signatures
	-- will be removed.
  if certAuthKey ~= nil and #certificates > 0 then
    log("Checking signatures...")
		-- Iterate backwards as we will be deleting from the list.
    for i=#certificates,1,-1 do
      local certificate = certificates[i]
      if certificate.signature == nil then
        if not allowUnsigned then
          log("Discarding "..certificate.name.." as it has no signature.")
          table.remove(certificates, i)
        end
      else
        local ok, valid = pcall(verifyCertificate, certificate, certAuthKey)
        if ok and valid then
					-- Keep the certificate.
          log(certificate.name.." has a valid signature.")
        else
          log("Discarding "..certificate.name.." as it has an invalid signature.")
          table.remove(certificates, i)
        end
      end
    end
  end

  return certificates
end


-- Request the certificate of a server with the given name.
-- Note that some servers may not respond to these requests,
-- expecting trusted clients to have been given the certificate manually.
-- All the certificates returned will contain the public key of their server.
--
-- If multiple certificates are received with the same server name,
-- there is no way to tell which one is the real server (the others are probably
-- malicious fakes), so none of them are returned. To avoid this situation,
-- this function can optionally use a certificate authority public key to
-- verify the signatures of received certificates, ignoring any with invalid
-- signatures. By default requestCertificate() looks in "certAuth.key"
-- for the key.
-- If multiple signed certificates are received, this implies that
-- the certificate authority has authorized an impersonator, so none of them
-- are returned as we don't know which is the real one.
--
-- serverName (string, required):
--   The name of the server to request the certificate of.
--
-- timeout (number, default: 1):
--   The length of time in seconds to wait for responses.
--   The function will always wait the full time, to allow for duplicates.
--
-- certAuthKey (table or string, default: "certAuth.key"):
--   The certificate authority public key used to verify signatures,
--   or the path of the file to load it from. If no valid key is found
--   the request will still go ahead, but signatures will not be checked.
--
-- allowUnsigned (boolean, default: false):
--   Whether to accept certificates with no valid signature.
--   If no valid cert auth key is provided this is ignored, as the certificates
--   cannot be checked without a key.
--
-- modemSide (string, default: a side with a modem):
--   The modem to use to send and receive messages.
--
-- Returns the certificate of the server if exactly one is received, or nil
-- if zero or more than one acceptable certificates are found.
-- Also returns a table of all acceptable certificates received.
function requestCertificate(serverName, timeout, certAuthKey, allowUnsigned, modemSide)
  if type(serverName) ~= "string" then
    error("Server name must be a string.", 2)
  end
  certAuthKey = loadCertAuthKey(certAuthKey)

  modemSide = resolveModemSide(modemSide)
  local modem = peripheral.wrap(modemSide)
  local channel = getChannel(serverName)
	-- Remember if the modem was already open so we can
	-- close it afterwards if it wasn't.
  local wasOpen = modem.isOpen(channel)
  modem.open(channel)

  log("Requesting certificate...")
  sendInternal(modemSide, channel, serverName, nil, "certificate_request")

	-- List of response message IDs we've already received
	-- so we can ignore duplicates.
  local receivedIDs = {}
	-- The received certificates.
  local certificates = {}
	-- Set a timer for when the timeout expires.
  local timer = os.startTimer((type(timeout) == "number") and timeout or 1)
  while true do
		-- Wait for either a modem_message or timer event.
    local event = {os.pullEvent()}
    if event[1] == "modem_message" and event[3] == channel then
			-- See if this is a CryptoNet-formatted message and exract its contents.
      local message = extractMessage(event[5], receivedIDs)
			-- If this is a certificate_response with a correctly formatted certifiate,
			-- for the correct server...
      if message ~= nil and message.msgType == "certificate_response" and certificateValid(message.message) and message.message.name == serverName then
        local certificate = message.message
        local found = false
				-- If we have already received an identical certificate don't add this one.
        for _,cert in pairs(certificates) do
          if certificate.key.public == cert.key.public and certificate.key.shared == cert.key.shared and certificate.signature == cert.signature then
            found = true
            break
          end
        end

        if not found then
          table.insert(certificates, certificate)
        end
      end
    elseif event[1] == "timer" and event[2] == timer then
			-- Stop listening for events once the time is up.
      break
    end
  end

	-- Close the channel if it wasn't open before we started.
  if not wasOpen then
    modem.close(channel)
  end

	-- If we have a valid cert auth key to use,
	-- verify the signatures of the received certificates.
	-- If allowUnsigned is false any certificates without valid signatures
	-- will be removed.
  local signedCount = 0
  if certAuthKey ~= nil and #certificates > 0 then
    log("Checking signatures...")
		-- Iterate backwards as we will be deleting from the list.
    for i=#certificates,1,-1 do
      local certificate = certificates[i]
      if certificate.signature == nil then
        if not allowUnsigned then
          log("Discarding a certificate as it has no signature.")
          table.remove(certificates, i)
        end
      else
        local ok, valid = pcall(verifyCertificate, certificate, certAuthKey)
        if ok and valid then
					-- Keep the certificate.
          log("This certificate has a valid signature.")
          signedCount = signedCount + 1
        else
          log("Discarding a certificate as it has an invalid signature.")
          table.remove(certificates, i)
        end
      end
    end
  end

  if #certificates == 1 then
    log("One certificate found, good.")
    return certificates[1], certificates
  else
    if #certificates == 0 then
      log("No certificates found.")
    elseif signedCount > 1 then
      log("Multiple ("..signedCount..") certificates had valid signatures, has the certificate authority authorized impersonators?")
    else
      log("Multiple ("..#certificates..") certificates found, some may be malicious.")
    end
		-- Don't return any certificate as the chosen one, but still return the whole list.
    return nil, certificates
  end
end


-- Open an encrypted connection to a CryptoNet server, returning a socket object
-- that can be used to send and receive messages from the server.
--
-- serverName (string, default: inferred from certificate):
--   The name of the server to connect to.
--
-- timeout (number, default: 5):
--   The number of seconds to wait for a response to the connection request.
--   Will terminate early if a response is received.
--
-- certTimeout (number, default: 1):
--   The number of seconds to wait for certificate responses,
--   if no certificate was provided.
--
-- certificate (table or string, default: "<serverName>.crt"):
--   The certificate of the server. Can either be the certificate of
--   the server itself, or the name of a file that contains it.
--   If no valid certificate is found a certificate request
--   will be sent to the server.
--
-- modemSide (string, default: a side with a modem):
--   The modem to use to send and receive messages.
--
-- certAuthKey (table or string, default: "certAuth.key"):
--   The certificate authority public key used to verify signatures,
--   or the path of the file to load it from. If no valid key is found
--   the connection will still go ahead, but signatures will not be checked.
--
-- allowUnsigned (boolean, default: false):
--   Whether to accept certificates with no valid signature.
--   If no valid cert auth key is provided this is ignored, as the certificates
--   cannot be checked without a key.
--   This does not apply to the certificate provided by the user (if present),
--   which is never verified (we trust them to get their own certificate right),
--   only to certificates received through a certificate request.
--
-- Returns a socket object that can be used to communicate with the server,
-- with the following attributes:
--  sender: The encrypted session key of this socket, which acts as the client's
--  		temporary identity to the server
--  target: The name of the server
--  key: The session key for this socket's session
--  modemSide: The modem used by the socket
--  channel: The channel the server (and this socket) use to communicate
--  permissionLevel: The permission level of the user logged into the socket,
-- 			initialized to 0.
--  receivedMessages: The encrypted messages received by this socket,
--  		used to prevent replay attacks using duplicate messages.
--  		Every time a message is encrypted the encrypted version will be different
--  		due to randomness in the algorithm, so if we get the exact same message
--		  twice it is probably a malicious duplicate.
function connect(serverName, timeout, certTimeout, certificate, modemSide, certAuthKey, allowUnsigned)
  if serverName ~= nil and type(serverName) ~= "string" then
    error("Server name must be a string or nil.", 2)
  end
  if certificate == nil then
    if type(serverName) == "string" then
			-- If a server name was given but not a certificate,
			-- try to load a corresponding certificate from file.
      certificate = serverName..".crt"
    else
			-- Need a way to identify the server.
      error("Server name and certificate can't both be nil.", 2)
    end
  end

	-- If the certificate is a file path...
  if type(certificate) == "string" then
    local certFilename = certificate
		-- Make paths relative to the current CryptoNet working directory.
    local certPath = workingDir == "" and certFilename or workingDir.."/"..certFilename
    log("Checking "..certPath.." for certificate...")
    if fs.isDir(certPath) or not fs.exists(certPath) then
			if fs.isDir(certPath) then
      	log(certFilename.." is not a file, will need to request certificate.")
			else
      	log(certFilename.." does not exist, will need to request certificate.")
			end
      certificate = nil
    else
      local file = fs.open(certPath, "r")
      certificate = deserializeCertOrKey(file.readAll())
      file.close()

      if not certificateValid(certificate) then
        log(certFilename.." does not contain a valid certificate, will need to request certificate.")
        certificate = nil
      else
        log("Loaded certificate from "..certFilename..".")
      end
    end
  elseif not certificateValid(certificate) then
		-- If certificate was not a string, it should be a valid certificate.
    error("Invalid certificate.", 2)
  end

	-- Infer serverName from the certificate.
  if serverName == nil then
    if certificate ~= nil then
      serverName = certificate.name
    else
      error("Failed to load name from certificate, and no name was provided.", 2)
    end
  end

  modemSide = resolveModemSide(modemSide)
  local modem = peripheral.wrap(modemSide)
  local channel = getChannel(serverName)
	-- Remember if the modem was already open so we can
	-- close it afterwards if it wasn't.
  local wasOpen = modem.isOpen(channel)
  modem.open(channel)

	-- If we have no certificate yet, request it from the server.
  if certificate == nil then
    certificate = requestCertificate(serverName, certTimeout, certAuthKey, allowUnsigned, modemSide)
    if certificate == nil then
			-- Close the modem channel if it wasn't open before we started.
      if not wasOpen then
        modem.close(channel)
      end
      error("Failed to request certificate from server.", 2)
    end
  end

	-- An AES session key is used to encrypt the messages sent and received over
	-- this socket. Before sending messages we need to generate a session key
	-- and send it to the server. RSA encryption using the server's public key
	-- (contained in its certificate) is used to send the session key;
	-- the server will use its private key to decrypt the message.
  log("Generating session key...")
  local sessKey = generateKey()
	local numKey = rsaCrypt.bytesToNumber(sessKey, 16*8, 8)
  local encryptedKey = rsaCrypt.crypt(certificate.key, numKey)
	-- The server will send a response encrypted with the session key to prove
	-- that it has received is successfully. We know what the response content
	-- is supposed to be, allowing us to verify the response.
  local expectedResponse = tostring(sha256.digest(serverName..certificate.key.public..certificate.key.shared..numKey))
  sendInternal(modemSide, channel, serverName, encryptedKey, "connection_request")

  log("Awaiting response...")
	-- List of response message IDs we've already received
	-- so we can ignore duplicates.
  local receivedIDs = {}
	-- Set a timer for when the timeout expires.
  local timer = os.startTimer((type(timeout) == "number") and timeout or 5)
  while true do
		-- Wait for either a modem_message or timer event.
    local event = {os.pullEvent()}
    if event[1] == "modem_message" and event[3] == channel then
			-- See if this is a CryptoNet-formatted message and exract its contents.
      local message = extractMessage(event[5], receivedIDs)
			-- If the message is a valid connection_response directed at this socket,
			-- containing a valid encrypted message...
      if message ~= nil and message.msgType == "connection_response" and message.target == encryptedKey and type(message.message) == "table"
			 and #message.message == 2 and type(message.message[1]) == "table" and type(message.message[2]) == "table" then
				 -- Decrypt using the session key.
        local ok, actualResponse = pcall(aes.decrypt_str, bytesToString(message.message[1]), sessKey, message.message[2])
				-- Compare the response to what we know the response content is supposed
				-- to be, to see if the session key was received correctly.
        if ok and actualResponse == expectedResponse then
          log("Connection successful.")
					-- Once we have received a valid response we know the connection has
					-- been opened on the server, so we can stop listening.
          os.cancelTimer(timer)
          break
        else
          log("Received an invalid response.")
        end
      end
    elseif event[1] == "timer" and event[2] == timer then
			-- If the timeout expires abort the connection attempt.
			-- Close the modem channel if it wasn't open before we started.
      if not wasOpen then
        modem.close(channel)
      end
      error("Did not receive a response before timeout.", 2)
    end
  end

	-- Create and return the socket object.
  local socket = {sender=encryptedKey, target=serverName, key=sessKey, modemSide=modemSide, channel=channel, permissionLevel=0, receivedMessages={}}
  table.insert(allClientSockets, socket)
  return socket
end


--
-- EVENT LOOP
--

-- Run a background loop that listens for events of any kind, and calls
-- an optional event handler on every event.
-- The event handler is always called in a new thread, so it is okay to use
-- blocking functions such as sleep() and pullEvent() within onEvent
-- without freezing the whole program. Errors raised during event handling
-- are printed without terminating the whole program, so errors processing one
-- event won't bring down the entire system.
--
-- Any modem_message events are also sent to CryptoNet for handling,
-- allowing all sockets and servers on this machine to listen for messages
-- in the background. Both the modem_message itself and any CryptoNet events invoked
-- by it are sent to the event handler, on seperate iterations of the event loop.
local function eventLoop(onEvent)
	-- List of response message IDs we've already received
	-- so we can ignore duplicates.
  local receivedIDs = {}
  while true do
		-- Wrap everything in pcall so any errors won't exit the entire program,
		-- only this iteration of the loop.
		local ok, msg = pcall(function()
			-- Listen for all event types.
	    local event = {os.pullEvent()}
	    if event[1] == "modem_message" then
	      local newEvent = handleModemEvent(event, receivedIDs)
	      if newEvent ~= nil then
					-- This event will be processed on a later iteration of the loop.
	        os.queueEvent(table.unpack(newEvent))
	      end
	    end
			-- Call the event handler in a new thread.
	    if onEvent ~= nil then
	      os.startThread(function ()
					-- We need another pcall here since this is in a different thread
					-- to the outer pcall, so that one won't be able to catch errors
					-- from the handler.
	        local ok, msg = pcall(onEvent, event)
					if not ok then
						-- Make sure pressing Ctrl+T can still terminate the program.
						if msg == "Terminated" then
							error("Terminated", 0)
						else
							-- Print the error without crashing.
							print(msg)
						end
					end
	      end)
	    end
		end)
		if not ok then
			-- Make sure pressing Ctrl+T can still terminate the program.
			if msg == "Terminated" then
				error("Terminated", 0)
			else
				-- Print the error without crashing.
				print(msg)
			end
		end
  end
end


-- Run a background loop that listens for events of any kind, and calls
-- the given event handler (which should take one argument) on them.
-- The event handler is always called in a new thread, so it is okay to use
-- blocking functions such as sleep() and pullEvent() within onEvent
-- without freezing the whole program. Errors raised during event handling
-- are printed without terminating the whole program, so errors processing one
-- event won't bring down the entire system.
--
-- Any modem_message events are also sent to CryptoNet for handling,
-- allowing all sockets and servers on this machine to listen for messages
-- in the background. Both the modem_message itself and any CryptoNet events invoked
-- by it are sent to the event handler, on separate iterations of the event loop.
--
-- The onStart function is called once after the loop starts,
-- after the threading system has been started.
-- onStart and onEvent are both optional.
-- os.startThread() can be called from within onStart and onEvent
-- (and any functions called by them) to start new threads without blocking
-- the current one.
function startEventLoop(onStart, onEvent)
  if onStart ~= nil and type(onStart) ~= "function" then
    error("onStart is not a function.", 2)
  end
  if onEvent ~= nil and type(onEvent) ~= "function" then
    error("onEvent is not a function.", 2)
  end

	-- Start the threading system so os.startThread() can be used.
  threadAPI.startThreading(function ()
		-- Start the actual event loop in a different thread.
    os.startThread(function () eventLoop(onEvent) end)
		-- Call onStart in this thread.
    if onStart ~= nil then
      local ok, msg = pcall(onStart)
      if not ok then
				-- Print the error without crashing.
        print(msg)
      end
    end
  end)
end


--
-- CERTIFICATE AUTHORITY
--

-- Generate the public and private keys used by a certificate authority
-- to sign certificates. The keys will be written to the specified files,
-- which both have sensible default names.
function initCertificateAuthority(publicFilename, privateFilename)
  if publicFilename == nil then
    publicFilename = "certAuth.key"
  end
  if privateFilename == nil then
    privateFilename = "certAuth_private.key"
  end
	-- Math paths relative to the current CryptoNet working directory.
  local publicPath = workingDir == "" and publicFilename or workingDir.."/"..publicFilename
  local privatePath = workingDir == "" and privateFilename or workingDir.."/"..privateFilename

  if fs.exists(publicPath) then
    error(publicPath.." already exists, please delete both your existing keyfiles in order to generate new ones.", 2)
  end
  if fs.exists(privatePath) then
    error(privatePath.." already exists, please delete both your existing keyfiles in order to generate new ones.", 2)
  end

  log("Generating key pair... (may take some time)")
  publicKey, privateKey = rsaKeygen.generateKeyPair()
  print("")
  log("Done!")

  local file = fs.open(publicPath, "w")
  file.write(serializeCertOrKey(publicKey))
  file.close()
  log("Saved public key to "..publicPath..".  Give this to client users.")

  file = fs.open(privatePath, "w")
  file.write(serializeCertOrKey(privateKey))
  file.close()
  log("Saved private key to "..privatePath..".  Do not share this with anyone!")

  log("Initialization successful.")
end


-- Sign a certificate using the certificate authority's private key.
-- Both arguments can either be the certificate/key itself, or a path to
-- a file that contains it. The signed certificate is returned, and written
-- to the path the certificate was stored in, if it was loaded from file.
function signCertificate(certificate, privateKey)
  local certPath = nil
  if type(certificate) == "string" then
		-- Make paths relative to the current CryptoNet working directory.
    certPath = workingDir == "" and certificate or workingDir.."/"..certificate
    if not fs.exists(certPath) then
      error(certPath.." does not exist.", 2)
    end
    if fs.isDir(certPath) then
      error(certPath.." is not a file.", 2)
    end

    local file = fs.open(certPath, "r")
    certificate = deserializeCertOrKey(file.readAll())
    file.close()

    if not certificateValid(certificate) then
      error(certPath.." does not contain a valid certificate.", 2)
    end
    log("Loaded certificate from "..certPath..".")
  elseif not certificateValid(certificate) then
		-- If certificate is not a file path it should be a valid certificate.
    error("Not a valid certificate or file.", 2)
  end

	-- Default value.
  if privateKey == nil then
    privateKey = "certAuth_private.key"
  end
  if type(privateKey) == "string" then
		-- Make paths relative to the current CryptoNet working directory.
    local keyPath = workingDir == "" and privateKey or workingDir.."/"..privateKey
    if not fs.exists(keyPath) then
      error(keyPath.." does not exist.", 2)
    end
    if fs.isDir(keyPath) then
      error(keyPath.." is not a file.", 2)
    end

    local file = fs.open(keyPath, "r")
    privateKey = deserializeCertOrKey(file.readAll())
    file.close()

    if not privateKeyValid(privateKey) then
      error(keyPath.." does not contain a valid private key.", 2)
    end
    log("Loaded private key from "..keyPath..".")
  elseif not privateKeyValid(privateKey) then
		-- If privateKey is not a file path it should be a valid private key.
    error("Not a valid private key or file.", 2)
  end

	-- The signature is just the contents of the certificate hashed and encrypted.
	-- Clients can verify the signature by decrypting it with the cert auth public key
	-- and seeing if it matches the contents of the certificate.
  log("Generating signature...")
  local hash = sha256.digest(certificate.name..certificate.key.public..certificate.key.shared)
  certificate.signature = rsaCrypt.crypt(privateKey, rsaCrypt.bytesToNumber(hash, 32*8, 8))

	-- If the certificate was loaded from a file, save it back there.
  if certPath ~= nil then
    local file = fs.open(certPath, "w")
    file.write(serializeCertOrKey(certificate))
    file.close()
    log("Saved certificate to "..certPath..".")
  end
  return certificate
end

-- CryptoNet's command line interface, used by a certificate authority
-- to sign certificates.
-- Supports two commands: initCertAuth and signCert.
--
-- initCertAuth is used to generate the keys used to sign and verify certificates.
-- The public key should be distributed to all clients using the certificate
-- authority, while the private key should be kept secure on the cert auth's
-- machine.
--
-- Certificates to be signed should be copied to the cert auth machine,
-- e.g. using floppy disks. signCert is then used to sign the certificate,
-- which can then be transferred back to the server machine.
-- Only sign the certificates of trusted servers, and don't sign two certificates
-- with the same name and different public keys.

-- Only run if executed on the command line, not when imported with os.loadAPI().
if shell ~= nil then
  setLoggingEnabled(true)
	-- Set the CryptoNet working directory to match the system one.
  setWorkingDirectory(shell.dir())

  local args = {...}
  if args[1] == "signCert" then
		-- Sign a certificate loaded from a file.
    local certPath = args[2]
    if certPath == nil then
      log("Usage: cryptoNet signCert <file>")
      return
    end

		-- Make paths relative to the working directory.
    certPath = workingDir == "" and certPath or workingDir.."/"..certPath
		-- Optional private key file argument, can be omitted to use default.
    local keyPath = args[3]
    local ok, msg = pcall(signCertificate, certPath, keyPath)

    if not ok then
      log("Error: "..msg:sub(8))
    end
  elseif args[1] == "initCertAuth" then
		-- Generate the cert auth key pair and save them to the specified files.
		-- The file arguments can be omitted to use the default values.
    local ok, msg = pcall(initCertificateAuthority, args[2], args[3])
    if not ok then
      log("Error: "..msg:sub(8))
    end
  else
    log("Invalid command.")
  end
end
