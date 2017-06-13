/**
 * @license
 * Copyright 2017 Yahoo Inc. All rights reserved.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

goog.provide('e2e.coname.vrf');

e2e.coname.vrf = (function() {
	var N2 = 32;
	var N = N2 / 2;
	var limit = 100;
	var cofactor = 8;

	var ed25519 = e2e.ecc.DomainParam.fromCurve(e2e.ecc.PrimeCurve.ED_25519);

	function OS2ECP(os, sign) {
		var b = os.slice();	// copy
		if (sign !== undefined)
			b[31] = (sign << 7) | (b[31] & 0x7f);
		try {
			return ed25519.curve.pointFromByteArray(b);
		} catch(e) {
		}
		return null;
	}

	function ECP2OS(P) {
		var os = P.toByteArray();
		var sign = os[31] >>> 7;
		os.unshift(sign + 2);
		return os;
	}

	function OS2IP(os) {
		return new e2e.BigNum(os);
	}

	function ECVRF_decode_proof(pi) {
		var i = 0;
		var sign = pi[i++];
		var r, c, s;
		if (sign != 2 && sign != 3)
			return;
		if (!(r = OS2ECP(pi.slice(i, i + N2), sign - 2)))
			return
		i += N2;
		c = pi.slice(i, i + N);
		i += N;
		s = pi.slice(i, i + N2);
		return {r: r, c: OS2IP(c), s: OS2IP(s)}
	}

	function ECVRF_hash_to_curve(m, pk) {
		var h = new e2e.hash.Sha256();
		var P;
		for (var i = 0; i < limit; i++) {
			var ctr = (e2e.BigNum.fromInteger(i)).toByteArray();
			for (var n = 4 - ctr.length; --n >= 0;) {
				ctr.unshift(0);
			}
			h.update(m);
			h.update(pk);
			h.update(ctr);
			var digest = h.digest();
			h.reset();
			if (P = OS2ECP(digest)) {
				// assume cofactor is 2^n
				for (var j = 1; j < cofactor; j *= 2)
					P = P.add(P);
				return P;
			}
		}
		// should not reach here
		throw new Error("couldn't make a point on curve")
	}

	/**
	 * @param {...number} var_args
	 */
	function ECVRF_hash_points(var_args) {
		var h = new e2e.hash.Sha256();
		for (var i = 0; i < arguments.length; i++) {
			h.update(ECP2OS(arguments[i]));
		}
		return OS2IP(h.digest().slice(0, N))
	}

	function ECVRF_verify(pk, pi, m) {
		var o = ECVRF_decode_proof(pi);
		if (!o)
			return false
		var P = OS2ECP(pk, pk[31] >>> 7);
		if (!P)
			return false
		// u = (g^x)^c * g^s = P^c * g^s
		var u = P.multiply(o.c).add(ed25519.curve.B.multiply(o.s));
		var h = ECVRF_hash_to_curve(m, pk);
		// v = gamma^c * h^s
		var v = o.r.multiply(o.c).add(h.multiply(o.s));
		// c' = ECVRF_hash_points(g, h, g^x, gamma, u, v)
		var c = ECVRF_hash_points(ed25519.curve.B, h, P, o.r, u, v);
		return c.isEqual(o.c)
	}

	return {
		verify: function(pk, m, vrf, proof) {
			if (!(vrf.length == N2 && proof.length > N2 + 1 && vrf.every(function(v, i) {return v === proof[i + 1]})))
				return false
			return ECVRF_verify(pk, proof, m);
		},

		// for testing
		hash_to_curve: function(m, pk) {
			return ECVRF_hash_to_curve(m, pk)
		}
	};
})();
