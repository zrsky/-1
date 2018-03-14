//接收数据的URL
//var baseurl = "didi.91xinxiang.com";//正式服
var baseurl = "didi.51zhcs.com"; //测试服
var siteurl = "http://" + baseurl;
//var app_version="1.06";
var app_version = "1.09";
var api_version = "v1";
var app_key = "144a6b229633360207ff9c79016fc494";
var app_iv = "144a6b2296333602";
var port = ":8080";

/*
CryptoJS v3.1.2 core 加密核心
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
var CryptoJS = CryptoJS || function(h, r) {
	var k = {},
		l = k.lib = {},
		n = function() {},
		f = l.Base = {
			extend: function(a) {
				n.prototype = this;
				var b = new n;
				a && b.mixIn(a);
				b.hasOwnProperty("init") || (b.init = function() {
					b.$super.init.apply(this, arguments)
				});
				b.init.prototype = b;
				b.$super = this;
				return b
			},
			create: function() {
				var a = this.extend();
				a.init.apply(a, arguments);
				return a
			},
			init: function() {},
			mixIn: function(a) {
				for(var b in a) a.hasOwnProperty(b) && (this[b] = a[b]);
				a.hasOwnProperty("toString") && (this.toString = a.toString)
			},
			clone: function() {
				return this.init.prototype.extend(this)
			}
		},
		j = l.WordArray = f.extend({
			init: function(a, b) {
				a = this.words = a || [];
				this.sigBytes = b != r ? b : 4 * a.length
			},
			toString: function(a) {
				return(a || s).stringify(this)
			},
			concat: function(a) {
				var b = this.words,
					d = a.words,
					c = this.sigBytes;
				a = a.sigBytes;
				this.clamp();
				if(c % 4)
					for(var e = 0; e < a; e++) b[c + e >>> 2] |= (d[e >>> 2] >>> 24 - 8 * (e % 4) & 255) << 24 - 8 * ((c + e) % 4);
				else if(65535 < d.length)
					for(e = 0; e < a; e += 4) b[c + e >>> 2] = d[e >>> 2];
				else b.push.apply(b, d);
				this.sigBytes += a;
				return this
			},
			clamp: function() {
				var a = this.words,
					b = this.sigBytes;
				a[b >>> 2] &= 4294967295 <<
					32 - 8 * (b % 4);
				a.length = h.ceil(b / 4)
			},
			clone: function() {
				var a = f.clone.call(this);
				a.words = this.words.slice(0);
				return a
			},
			random: function(a) {
				for(var b = [], d = 0; d < a; d += 4) b.push(4294967296 * h.random() | 0);
				return new j.init(b, a)
			}
		}),
		m = k.enc = {},
		s = m.Hex = {
			stringify: function(a) {
				var b = a.words;
				a = a.sigBytes;
				for(var d = [], c = 0; c < a; c++) {
					var e = b[c >>> 2] >>> 24 - 8 * (c % 4) & 255;
					d.push((e >>> 4).toString(16));
					d.push((e & 15).toString(16))
				}
				return d.join("")
			},
			parse: function(a) {
				for(var b = a.length, d = [], c = 0; c < b; c += 2) d[c >>> 3] |= parseInt(a.substr(c,
					2), 16) << 24 - 4 * (c % 8);
				return new j.init(d, b / 2)
			}
		},
		p = m.Latin1 = {
			stringify: function(a) {
				var b = a.words;
				a = a.sigBytes;
				for(var d = [], c = 0; c < a; c++) d.push(String.fromCharCode(b[c >>> 2] >>> 24 - 8 * (c % 4) & 255));
				return d.join("")
			},
			parse: function(a) {
				for(var b = a.length, d = [], c = 0; c < b; c++) d[c >>> 2] |= (a.charCodeAt(c) & 255) << 24 - 8 * (c % 4);
				return new j.init(d, b)
			}
		},
		t = m.Utf8 = {
			stringify: function(a) {
				try {
					return decodeURIComponent(escape(p.stringify(a)))
				} catch(b) {
					throw Error("Malformed UTF-8 data");
				}
			},
			parse: function(a) {
				return p.parse(unescape(encodeURIComponent(a)))
			}
		},
		q = l.BufferedBlockAlgorithm = f.extend({
			reset: function() {
				this._data = new j.init;
				this._nDataBytes = 0
			},
			_append: function(a) {
				"string" == typeof a && (a = t.parse(a));
				this._data.concat(a);
				this._nDataBytes += a.sigBytes
			},
			_process: function(a) {
				var b = this._data,
					d = b.words,
					c = b.sigBytes,
					e = this.blockSize,
					f = c / (4 * e),
					f = a ? h.ceil(f) : h.max((f | 0) - this._minBufferSize, 0);
				a = f * e;
				c = h.min(4 * a, c);
				if(a) {
					for(var g = 0; g < a; g += e) this._doProcessBlock(d, g);
					g = d.splice(0, a);
					b.sigBytes -= c
				}
				return new j.init(g, c)
			},
			clone: function() {
				var a = f.clone.call(this);
				a._data = this._data.clone();
				return a
			},
			_minBufferSize: 0
		});
	l.Hasher = q.extend({
		cfg: f.extend(),
		init: function(a) {
			this.cfg = this.cfg.extend(a);
			this.reset()
		},
		reset: function() {
			q.reset.call(this);
			this._doReset()
		},
		update: function(a) {
			this._append(a);
			this._process();
			return this
		},
		finalize: function(a) {
			a && this._append(a);
			return this._doFinalize()
		},
		blockSize: 16,
		_createHelper: function(a) {
			return function(b, d) {
				return(new a.init(d)).finalize(b)
			}
		},
		_createHmacHelper: function(a) {
			return function(b, d) {
				return(new u.HMAC.init(a,
					d)).finalize(b)
			}
		}
	});
	var u = k.algo = {};
	return k
}(Math);

/*
CryptoJS v3.1.2 aes
code.google.com/p/crypto-js AES加密算法
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
var CryptoJS = CryptoJS || function(u, p) {
	var d = {},
		l = d.lib = {},
		s = function() {},
		t = l.Base = {
			extend: function(a) {
				s.prototype = this;
				var c = new s;
				a && c.mixIn(a);
				c.hasOwnProperty("init") || (c.init = function() {
					c.$super.init.apply(this, arguments)
				});
				c.init.prototype = c;
				c.$super = this;
				return c
			},
			create: function() {
				var a = this.extend();
				a.init.apply(a, arguments);
				return a
			},
			init: function() {},
			mixIn: function(a) {
				for(var c in a) a.hasOwnProperty(c) && (this[c] = a[c]);
				a.hasOwnProperty("toString") && (this.toString = a.toString)
			},
			clone: function() {
				return this.init.prototype.extend(this)
			}
		},
		r = l.WordArray = t.extend({
			init: function(a, c) {
				a = this.words = a || [];
				this.sigBytes = c != p ? c : 4 * a.length
			},
			toString: function(a) {
				return(a || v).stringify(this)
			},
			concat: function(a) {
				var c = this.words,
					e = a.words,
					j = this.sigBytes;
				a = a.sigBytes;
				this.clamp();
				if(j % 4)
					for(var k = 0; k < a; k++) c[j + k >>> 2] |= (e[k >>> 2] >>> 24 - 8 * (k % 4) & 255) << 24 - 8 * ((j + k) % 4);
				else if(65535 < e.length)
					for(k = 0; k < a; k += 4) c[j + k >>> 2] = e[k >>> 2];
				else c.push.apply(c, e);
				this.sigBytes += a;
				return this
			},
			clamp: function() {
				var a = this.words,
					c = this.sigBytes;
				a[c >>> 2] &= 4294967295 <<
					32 - 8 * (c % 4);
				a.length = u.ceil(c / 4)
			},
			clone: function() {
				var a = t.clone.call(this);
				a.words = this.words.slice(0);
				return a
			},
			random: function(a) {
				for(var c = [], e = 0; e < a; e += 4) c.push(4294967296 * u.random() | 0);
				return new r.init(c, a)
			}
		}),
		w = d.enc = {},
		v = w.Hex = {
			stringify: function(a) {
				var c = a.words;
				a = a.sigBytes;
				for(var e = [], j = 0; j < a; j++) {
					var k = c[j >>> 2] >>> 24 - 8 * (j % 4) & 255;
					e.push((k >>> 4).toString(16));
					e.push((k & 15).toString(16))
				}
				return e.join("")
			},
			parse: function(a) {
				for(var c = a.length, e = [], j = 0; j < c; j += 2) e[j >>> 3] |= parseInt(a.substr(j,
					2), 16) << 24 - 4 * (j % 8);
				return new r.init(e, c / 2)
			}
		},
		b = w.Latin1 = {
			stringify: function(a) {
				var c = a.words;
				a = a.sigBytes;
				for(var e = [], j = 0; j < a; j++) e.push(String.fromCharCode(c[j >>> 2] >>> 24 - 8 * (j % 4) & 255));
				return e.join("")
			},
			parse: function(a) {
				for(var c = a.length, e = [], j = 0; j < c; j++) e[j >>> 2] |= (a.charCodeAt(j) & 255) << 24 - 8 * (j % 4);
				return new r.init(e, c)
			}
		},
		x = w.Utf8 = {
			stringify: function(a) {
				try {
					return decodeURIComponent(escape(b.stringify(a)))
				} catch(c) {
					throw Error("Malformed UTF-8 data");
				}
			},
			parse: function(a) {
				return b.parse(unescape(encodeURIComponent(a)))
			}
		},
		q = l.BufferedBlockAlgorithm = t.extend({
			reset: function() {
				this._data = new r.init;
				this._nDataBytes = 0
			},
			_append: function(a) {
				"string" == typeof a && (a = x.parse(a));
				this._data.concat(a);
				this._nDataBytes += a.sigBytes
			},
			_process: function(a) {
				var c = this._data,
					e = c.words,
					j = c.sigBytes,
					k = this.blockSize,
					b = j / (4 * k),
					b = a ? u.ceil(b) : u.max((b | 0) - this._minBufferSize, 0);
				a = b * k;
				j = u.min(4 * a, j);
				if(a) {
					for(var q = 0; q < a; q += k) this._doProcessBlock(e, q);
					q = e.splice(0, a);
					c.sigBytes -= j
				}
				return new r.init(q, j)
			},
			clone: function() {
				var a = t.clone.call(this);
				a._data = this._data.clone();
				return a
			},
			_minBufferSize: 0
		});
	l.Hasher = q.extend({
		cfg: t.extend(),
		init: function(a) {
			this.cfg = this.cfg.extend(a);
			this.reset()
		},
		reset: function() {
			q.reset.call(this);
			this._doReset()
		},
		update: function(a) {
			this._append(a);
			this._process();
			return this
		},
		finalize: function(a) {
			a && this._append(a);
			return this._doFinalize()
		},
		blockSize: 16,
		_createHelper: function(a) {
			return function(b, e) {
				return(new a.init(e)).finalize(b)
			}
		},
		_createHmacHelper: function(a) {
			return function(b, e) {
				return(new n.HMAC.init(a,
					e)).finalize(b)
			}
		}
	});
	var n = d.algo = {};
	return d
}(Math);
(function() {
	var u = CryptoJS,
		p = u.lib.WordArray;
	u.enc.Base64 = {
		stringify: function(d) {
			var l = d.words,
				p = d.sigBytes,
				t = this._map;
			d.clamp();
			d = [];
			for(var r = 0; r < p; r += 3)
				for(var w = (l[r >>> 2] >>> 24 - 8 * (r % 4) & 255) << 16 | (l[r + 1 >>> 2] >>> 24 - 8 * ((r + 1) % 4) & 255) << 8 | l[r + 2 >>> 2] >>> 24 - 8 * ((r + 2) % 4) & 255, v = 0; 4 > v && r + 0.75 * v < p; v++) d.push(t.charAt(w >>> 6 * (3 - v) & 63));
			if(l = t.charAt(64))
				for(; d.length % 4;) d.push(l);
			return d.join("")
		},
		parse: function(d) {
			var l = d.length,
				s = this._map,
				t = s.charAt(64);
			t && (t = d.indexOf(t), -1 != t && (l = t));
			for(var t = [], r = 0, w = 0; w <
				l; w++)
				if(w % 4) {
					var v = s.indexOf(d.charAt(w - 1)) << 2 * (w % 4),
						b = s.indexOf(d.charAt(w)) >>> 6 - 2 * (w % 4);
					t[r >>> 2] |= (v | b) << 24 - 8 * (r % 4);
					r++
				}
			return p.create(t, r)
		},
		_map: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	}
})();
(function(u) {
	function p(b, n, a, c, e, j, k) {
		b = b + (n & a | ~n & c) + e + k;
		return(b << j | b >>> 32 - j) + n
	}

	function d(b, n, a, c, e, j, k) {
		b = b + (n & c | a & ~c) + e + k;
		return(b << j | b >>> 32 - j) + n
	}

	function l(b, n, a, c, e, j, k) {
		b = b + (n ^ a ^ c) + e + k;
		return(b << j | b >>> 32 - j) + n
	}

	function s(b, n, a, c, e, j, k) {
		b = b + (a ^ (n | ~c)) + e + k;
		return(b << j | b >>> 32 - j) + n
	}
	for(var t = CryptoJS, r = t.lib, w = r.WordArray, v = r.Hasher, r = t.algo, b = [], x = 0; 64 > x; x++) b[x] = 4294967296 * u.abs(u.sin(x + 1)) | 0;
	r = r.MD5 = v.extend({
		_doReset: function() {
			this._hash = new w.init([1732584193, 4023233417, 2562383102, 271733878])
		},
		_doProcessBlock: function(q, n) {
			for(var a = 0; 16 > a; a++) {
				var c = n + a,
					e = q[c];
				q[c] = (e << 8 | e >>> 24) & 16711935 | (e << 24 | e >>> 8) & 4278255360
			}
			var a = this._hash.words,
				c = q[n + 0],
				e = q[n + 1],
				j = q[n + 2],
				k = q[n + 3],
				z = q[n + 4],
				r = q[n + 5],
				t = q[n + 6],
				w = q[n + 7],
				v = q[n + 8],
				A = q[n + 9],
				B = q[n + 10],
				C = q[n + 11],
				u = q[n + 12],
				D = q[n + 13],
				E = q[n + 14],
				x = q[n + 15],
				f = a[0],
				m = a[1],
				g = a[2],
				h = a[3],
				f = p(f, m, g, h, c, 7, b[0]),
				h = p(h, f, m, g, e, 12, b[1]),
				g = p(g, h, f, m, j, 17, b[2]),
				m = p(m, g, h, f, k, 22, b[3]),
				f = p(f, m, g, h, z, 7, b[4]),
				h = p(h, f, m, g, r, 12, b[5]),
				g = p(g, h, f, m, t, 17, b[6]),
				m = p(m, g, h, f, w, 22, b[7]),
				f = p(f, m, g, h, v, 7, b[8]),
				h = p(h, f, m, g, A, 12, b[9]),
				g = p(g, h, f, m, B, 17, b[10]),
				m = p(m, g, h, f, C, 22, b[11]),
				f = p(f, m, g, h, u, 7, b[12]),
				h = p(h, f, m, g, D, 12, b[13]),
				g = p(g, h, f, m, E, 17, b[14]),
				m = p(m, g, h, f, x, 22, b[15]),
				f = d(f, m, g, h, e, 5, b[16]),
				h = d(h, f, m, g, t, 9, b[17]),
				g = d(g, h, f, m, C, 14, b[18]),
				m = d(m, g, h, f, c, 20, b[19]),
				f = d(f, m, g, h, r, 5, b[20]),
				h = d(h, f, m, g, B, 9, b[21]),
				g = d(g, h, f, m, x, 14, b[22]),
				m = d(m, g, h, f, z, 20, b[23]),
				f = d(f, m, g, h, A, 5, b[24]),
				h = d(h, f, m, g, E, 9, b[25]),
				g = d(g, h, f, m, k, 14, b[26]),
				m = d(m, g, h, f, v, 20, b[27]),
				f = d(f, m, g, h, D, 5, b[28]),
				h = d(h, f,
					m, g, j, 9, b[29]),
				g = d(g, h, f, m, w, 14, b[30]),
				m = d(m, g, h, f, u, 20, b[31]),
				f = l(f, m, g, h, r, 4, b[32]),
				h = l(h, f, m, g, v, 11, b[33]),
				g = l(g, h, f, m, C, 16, b[34]),
				m = l(m, g, h, f, E, 23, b[35]),
				f = l(f, m, g, h, e, 4, b[36]),
				h = l(h, f, m, g, z, 11, b[37]),
				g = l(g, h, f, m, w, 16, b[38]),
				m = l(m, g, h, f, B, 23, b[39]),
				f = l(f, m, g, h, D, 4, b[40]),
				h = l(h, f, m, g, c, 11, b[41]),
				g = l(g, h, f, m, k, 16, b[42]),
				m = l(m, g, h, f, t, 23, b[43]),
				f = l(f, m, g, h, A, 4, b[44]),
				h = l(h, f, m, g, u, 11, b[45]),
				g = l(g, h, f, m, x, 16, b[46]),
				m = l(m, g, h, f, j, 23, b[47]),
				f = s(f, m, g, h, c, 6, b[48]),
				h = s(h, f, m, g, w, 10, b[49]),
				g = s(g, h, f, m,
					E, 15, b[50]),
				m = s(m, g, h, f, r, 21, b[51]),
				f = s(f, m, g, h, u, 6, b[52]),
				h = s(h, f, m, g, k, 10, b[53]),
				g = s(g, h, f, m, B, 15, b[54]),
				m = s(m, g, h, f, e, 21, b[55]),
				f = s(f, m, g, h, v, 6, b[56]),
				h = s(h, f, m, g, x, 10, b[57]),
				g = s(g, h, f, m, t, 15, b[58]),
				m = s(m, g, h, f, D, 21, b[59]),
				f = s(f, m, g, h, z, 6, b[60]),
				h = s(h, f, m, g, C, 10, b[61]),
				g = s(g, h, f, m, j, 15, b[62]),
				m = s(m, g, h, f, A, 21, b[63]);
			a[0] = a[0] + f | 0;
			a[1] = a[1] + m | 0;
			a[2] = a[2] + g | 0;
			a[3] = a[3] + h | 0
		},
		_doFinalize: function() {
			var b = this._data,
				n = b.words,
				a = 8 * this._nDataBytes,
				c = 8 * b.sigBytes;
			n[c >>> 5] |= 128 << 24 - c % 32;
			var e = u.floor(a /
				4294967296);
			n[(c + 64 >>> 9 << 4) + 15] = (e << 8 | e >>> 24) & 16711935 | (e << 24 | e >>> 8) & 4278255360;
			n[(c + 64 >>> 9 << 4) + 14] = (a << 8 | a >>> 24) & 16711935 | (a << 24 | a >>> 8) & 4278255360;
			b.sigBytes = 4 * (n.length + 1);
			this._process();
			b = this._hash;
			n = b.words;
			for(a = 0; 4 > a; a++) c = n[a], n[a] = (c << 8 | c >>> 24) & 16711935 | (c << 24 | c >>> 8) & 4278255360;
			return b
		},
		clone: function() {
			var b = v.clone.call(this);
			b._hash = this._hash.clone();
			return b
		}
	});
	t.MD5 = v._createHelper(r);
	t.HmacMD5 = v._createHmacHelper(r)
})(Math);
(function() {
	var u = CryptoJS,
		p = u.lib,
		d = p.Base,
		l = p.WordArray,
		p = u.algo,
		s = p.EvpKDF = d.extend({
			cfg: d.extend({
				keySize: 4,
				hasher: p.MD5,
				iterations: 1
			}),
			init: function(d) {
				this.cfg = this.cfg.extend(d)
			},
			compute: function(d, r) {
				for(var p = this.cfg, s = p.hasher.create(), b = l.create(), u = b.words, q = p.keySize, p = p.iterations; u.length < q;) {
					n && s.update(n);
					var n = s.update(d).finalize(r);
					s.reset();
					for(var a = 1; a < p; a++) n = s.finalize(n), s.reset();
					b.concat(n)
				}
				b.sigBytes = 4 * q;
				return b
			}
		});
	u.EvpKDF = function(d, l, p) {
		return s.create(p).compute(d,
			l)
	}
})();
CryptoJS.lib.Cipher || function(u) {
	var p = CryptoJS,
		d = p.lib,
		l = d.Base,
		s = d.WordArray,
		t = d.BufferedBlockAlgorithm,
		r = p.enc.Base64,
		w = p.algo.EvpKDF,
		v = d.Cipher = t.extend({
			cfg: l.extend(),
			createEncryptor: function(e, a) {
				return this.create(this._ENC_XFORM_MODE, e, a)
			},
			createDecryptor: function(e, a) {
				return this.create(this._DEC_XFORM_MODE, e, a)
			},
			init: function(e, a, b) {
				this.cfg = this.cfg.extend(b);
				this._xformMode = e;
				this._key = a;
				this.reset()
			},
			reset: function() {
				t.reset.call(this);
				this._doReset()
			},
			process: function(e) {
				this._append(e);
				return this._process()
			},
			finalize: function(e) {
				e && this._append(e);
				return this._doFinalize()
			},
			keySize: 4,
			ivSize: 4,
			_ENC_XFORM_MODE: 1,
			_DEC_XFORM_MODE: 2,
			_createHelper: function(e) {
				return {
					encrypt: function(b, k, d) {
						return("string" == typeof k ? c : a).encrypt(e, b, k, d)
					},
					decrypt: function(b, k, d) {
						return("string" == typeof k ? c : a).decrypt(e, b, k, d)
					}
				}
			}
		});
	d.StreamCipher = v.extend({
		_doFinalize: function() {
			return this._process(!0)
		},
		blockSize: 1
	});
	var b = p.mode = {},
		x = function(e, a, b) {
			var c = this._iv;
			c ? this._iv = u : c = this._prevBlock;
			for(var d = 0; d < b; d++) e[a + d] ^=
				c[d]
		},
		q = (d.BlockCipherMode = l.extend({
			createEncryptor: function(e, a) {
				return this.Encryptor.create(e, a)
			},
			createDecryptor: function(e, a) {
				return this.Decryptor.create(e, a)
			},
			init: function(e, a) {
				this._cipher = e;
				this._iv = a
			}
		})).extend();
	q.Encryptor = q.extend({
		processBlock: function(e, a) {
			var b = this._cipher,
				c = b.blockSize;
			x.call(this, e, a, c);
			b.encryptBlock(e, a);
			this._prevBlock = e.slice(a, a + c)
		}
	});
	q.Decryptor = q.extend({
		processBlock: function(e, a) {
			var b = this._cipher,
				c = b.blockSize,
				d = e.slice(a, a + c);
			b.decryptBlock(e, a);
			x.call(this,
				e, a, c);
			this._prevBlock = d
		}
	});
	b = b.CBC = q;
	q = (p.pad = {}).Pkcs7 = {
		pad: function(a, b) {
			for(var c = 4 * b, c = c - a.sigBytes % c, d = c << 24 | c << 16 | c << 8 | c, l = [], n = 0; n < c; n += 4) l.push(d);
			c = s.create(l, c);
			a.concat(c)
		},
		unpad: function(a) {
			a.sigBytes -= a.words[a.sigBytes - 1 >>> 2] & 255
		}
	};
	d.BlockCipher = v.extend({
		cfg: v.cfg.extend({
			mode: b,
			padding: q
		}),
		reset: function() {
			v.reset.call(this);
			var a = this.cfg,
				b = a.iv,
				a = a.mode;
			if(this._xformMode == this._ENC_XFORM_MODE) var c = a.createEncryptor;
			else c = a.createDecryptor, this._minBufferSize = 1;
			this._mode = c.call(a,
				this, b && b.words)
		},
		_doProcessBlock: function(a, b) {
			this._mode.processBlock(a, b)
		},
		_doFinalize: function() {
			var a = this.cfg.padding;
			if(this._xformMode == this._ENC_XFORM_MODE) {
				a.pad(this._data, this.blockSize);
				var b = this._process(!0)
			} else b = this._process(!0), a.unpad(b);
			return b
		},
		blockSize: 4
	});
	var n = d.CipherParams = l.extend({
			init: function(a) {
				this.mixIn(a)
			},
			toString: function(a) {
				return(a || this.formatter).stringify(this)
			}
		}),
		b = (p.format = {}).OpenSSL = {
			stringify: function(a) {
				var b = a.ciphertext;
				a = a.salt;
				return(a ? s.create([1398893684,
					1701076831
				]).concat(a).concat(b) : b).toString(r)
			},
			parse: function(a) {
				a = r.parse(a);
				var b = a.words;
				if(1398893684 == b[0] && 1701076831 == b[1]) {
					var c = s.create(b.slice(2, 4));
					b.splice(0, 4);
					a.sigBytes -= 16
				}
				return n.create({
					ciphertext: a,
					salt: c
				})
			}
		},
		a = d.SerializableCipher = l.extend({
			cfg: l.extend({
				format: b
			}),
			encrypt: function(a, b, c, d) {
				d = this.cfg.extend(d);
				var l = a.createEncryptor(c, d);
				b = l.finalize(b);
				l = l.cfg;
				return n.create({
					ciphertext: b,
					key: c,
					iv: l.iv,
					algorithm: a,
					mode: l.mode,
					padding: l.padding,
					blockSize: a.blockSize,
					formatter: d.format
				})
			},
			decrypt: function(a, b, c, d) {
				d = this.cfg.extend(d);
				b = this._parse(b, d.format);
				return a.createDecryptor(c, d).finalize(b.ciphertext)
			},
			_parse: function(a, b) {
				return "string" == typeof a ? b.parse(a, this) : a
			}
		}),
		p = (p.kdf = {}).OpenSSL = {
			execute: function(a, b, c, d) {
				d || (d = s.random(8));
				a = w.create({
					keySize: b + c
				}).compute(a, d);
				c = s.create(a.words.slice(b), 4 * c);
				a.sigBytes = 4 * b;
				return n.create({
					key: a,
					iv: c,
					salt: d
				})
			}
		},
		c = d.PasswordBasedCipher = a.extend({
			cfg: a.cfg.extend({
				kdf: p
			}),
			encrypt: function(b, c, d, l) {
				l = this.cfg.extend(l);
				d = l.kdf.execute(d,
					b.keySize, b.ivSize);
				l.iv = d.iv;
				b = a.encrypt.call(this, b, c, d.key, l);
				b.mixIn(d);
				return b
			},
			decrypt: function(b, c, d, l) {
				l = this.cfg.extend(l);
				c = this._parse(c, l.format);
				d = l.kdf.execute(d, b.keySize, b.ivSize, c.salt);
				l.iv = d.iv;
				return a.decrypt.call(this, b, c, d.key, l)
			}
		})
}();
(function() {
	for(var u = CryptoJS, p = u.lib.BlockCipher, d = u.algo, l = [], s = [], t = [], r = [], w = [], v = [], b = [], x = [], q = [], n = [], a = [], c = 0; 256 > c; c++) a[c] = 128 > c ? c << 1 : c << 1 ^ 283;
	for(var e = 0, j = 0, c = 0; 256 > c; c++) {
		var k = j ^ j << 1 ^ j << 2 ^ j << 3 ^ j << 4,
			k = k >>> 8 ^ k & 255 ^ 99;
		l[e] = k;
		s[k] = e;
		var z = a[e],
			F = a[z],
			G = a[F],
			y = 257 * a[k] ^ 16843008 * k;
		t[e] = y << 24 | y >>> 8;
		r[e] = y << 16 | y >>> 16;
		w[e] = y << 8 | y >>> 24;
		v[e] = y;
		y = 16843009 * G ^ 65537 * F ^ 257 * z ^ 16843008 * e;
		b[k] = y << 24 | y >>> 8;
		x[k] = y << 16 | y >>> 16;
		q[k] = y << 8 | y >>> 24;
		n[k] = y;
		e ? (e = z ^ a[a[a[G ^ z]]], j ^= a[a[j]]) : e = j = 1
	}
	var H = [0, 1, 2, 4, 8,
			16, 32, 64, 128, 27, 54
		],
		d = d.AES = p.extend({
			_doReset: function() {
				for(var a = this._key, c = a.words, d = a.sigBytes / 4, a = 4 * ((this._nRounds = d + 6) + 1), e = this._keySchedule = [], j = 0; j < a; j++)
					if(j < d) e[j] = c[j];
					else {
						var k = e[j - 1];
						j % d ? 6 < d && 4 == j % d && (k = l[k >>> 24] << 24 | l[k >>> 16 & 255] << 16 | l[k >>> 8 & 255] << 8 | l[k & 255]) : (k = k << 8 | k >>> 24, k = l[k >>> 24] << 24 | l[k >>> 16 & 255] << 16 | l[k >>> 8 & 255] << 8 | l[k & 255], k ^= H[j / d | 0] << 24);
						e[j] = e[j - d] ^ k
					}
				c = this._invKeySchedule = [];
				for(d = 0; d < a; d++) j = a - d, k = d % 4 ? e[j] : e[j - 4], c[d] = 4 > d || 4 >= j ? k : b[l[k >>> 24]] ^ x[l[k >>> 16 & 255]] ^ q[l[k >>>
					8 & 255]] ^ n[l[k & 255]]
			},
			encryptBlock: function(a, b) {
				this._doCryptBlock(a, b, this._keySchedule, t, r, w, v, l)
			},
			decryptBlock: function(a, c) {
				var d = a[c + 1];
				a[c + 1] = a[c + 3];
				a[c + 3] = d;
				this._doCryptBlock(a, c, this._invKeySchedule, b, x, q, n, s);
				d = a[c + 1];
				a[c + 1] = a[c + 3];
				a[c + 3] = d
			},
			_doCryptBlock: function(a, b, c, d, e, j, l, f) {
				for(var m = this._nRounds, g = a[b] ^ c[0], h = a[b + 1] ^ c[1], k = a[b + 2] ^ c[2], n = a[b + 3] ^ c[3], p = 4, r = 1; r < m; r++) var q = d[g >>> 24] ^ e[h >>> 16 & 255] ^ j[k >>> 8 & 255] ^ l[n & 255] ^ c[p++],
					s = d[h >>> 24] ^ e[k >>> 16 & 255] ^ j[n >>> 8 & 255] ^ l[g & 255] ^ c[p++],
					t =
					d[k >>> 24] ^ e[n >>> 16 & 255] ^ j[g >>> 8 & 255] ^ l[h & 255] ^ c[p++],
					n = d[n >>> 24] ^ e[g >>> 16 & 255] ^ j[h >>> 8 & 255] ^ l[k & 255] ^ c[p++],
					g = q,
					h = s,
					k = t;
				q = (f[g >>> 24] << 24 | f[h >>> 16 & 255] << 16 | f[k >>> 8 & 255] << 8 | f[n & 255]) ^ c[p++];
				s = (f[h >>> 24] << 24 | f[k >>> 16 & 255] << 16 | f[n >>> 8 & 255] << 8 | f[g & 255]) ^ c[p++];
				t = (f[k >>> 24] << 24 | f[n >>> 16 & 255] << 16 | f[g >>> 8 & 255] << 8 | f[h & 255]) ^ c[p++];
				n = (f[n >>> 24] << 24 | f[g >>> 16 & 255] << 16 | f[h >>> 8 & 255] << 8 | f[k & 255]) ^ c[p++];
				a[b] = q;
				a[b + 1] = s;
				a[b + 2] = t;
				a[b + 3] = n
			},
			keySize: 8
		});
	u.AES = p._createHelper(d)
})();

/*
CryptoJS v3.1.2 mode-ecb aes加密ecb模式算法
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
CryptoJS.mode.ECB = function() {
	var a = CryptoJS.lib.BlockCipherMode.extend();
	a.Encryptor = a.extend({
		processBlock: function(a, b) {
			this._cipher.encryptBlock(a, b)
		}
	});
	a.Decryptor = a.extend({
		processBlock: function(a, b) {
			this._cipher.decryptBlock(a, b)
		}
	});
	return a
}();

/*
CryptoJS v3.1.2 lib-typearrays cryptpjs加密需要用到的typearrays对象
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function() {
	if("function" == typeof ArrayBuffer) {
		var b = CryptoJS.lib.WordArray,
			e = b.init;
		(b.init = function(a) {
			a instanceof ArrayBuffer && (a = new Uint8Array(a));
			if(a instanceof Int8Array || a instanceof Uint8ClampedArray || a instanceof Int16Array || a instanceof Uint16Array || a instanceof Int32Array || a instanceof Uint32Array || a instanceof Float32Array || a instanceof Float64Array) a = new Uint8Array(a.buffer, a.byteOffset, a.byteLength);
			if(a instanceof Uint8Array) {
				for(var b = a.byteLength, d = [], c = 0; c < b; c++) d[c >>> 2] |= a[c] <<
					24 - 8 * (c % 4);
				e.call(this, d, b)
			} else e.apply(this, arguments)
		}).prototype = b
	}
})();

/*
CryptoJS v3.1.2 pad-nopadding aes加密填充类型
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
CryptoJS.pad.NoPadding = {
	pad: function() {},
	unpad: function() {}
};

/*
CryptoJS v3.1.2 enc.base64
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function() {
	var h = CryptoJS,
		j = h.lib.WordArray;
	h.enc.Base64 = {
		stringify: function(b) {
			var e = b.words,
				f = b.sigBytes,
				c = this._map;
			b.clamp();
			b = [];
			for(var a = 0; a < f; a += 3)
				for(var d = (e[a >>> 2] >>> 24 - 8 * (a % 4) & 255) << 16 | (e[a + 1 >>> 2] >>> 24 - 8 * ((a + 1) % 4) & 255) << 8 | e[a + 2 >>> 2] >>> 24 - 8 * ((a + 2) % 4) & 255, g = 0; 4 > g && a + 0.75 * g < f; g++) b.push(c.charAt(d >>> 6 * (3 - g) & 63));
			if(e = c.charAt(64))
				for(; b.length % 4;) b.push(e);
			return b.join("")
		},
		parse: function(b) {
			var e = b.length,
				f = this._map,
				c = f.charAt(64);
			c && (c = b.indexOf(c), -1 != c && (e = c));
			for(var c = [], a = 0, d = 0; d <
				e; d++)
				if(d % 4) {
					var g = f.indexOf(b.charAt(d - 1)) << 2 * (d % 4),
						h = f.indexOf(b.charAt(d)) >>> 6 - 2 * (d % 4);
					c[a >>> 2] |= (g | h) << 24 - 8 * (a % 4);
					a++
				}
			return j.create(c, a)
		},
		_map: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	}
})();

//加密
function encrypt(input) {
	var key = CryptoJS.enc.Utf8.parse(app_key);
	var iv = CryptoJS.lib.WordArray.random(8).toString(CryptoJS.enc.Hex);
	var encrypted = CryptoJS.AES.encrypt(input, key, {
		iv: CryptoJS.enc.Utf8.parse(iv),
		format: CryptoJS.format.OpenSSL
	});
	var out = iv + encrypted;
	var str = CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(out));
	return str.toString();
}

function decrypt(input) {
	//解密
	var str = CryptoJS.enc.Base64.parse(input);
	str = str.toString(CryptoJS.enc.Utf8);
	var key = CryptoJS.enc.Utf8.parse(app_key);
	var iv = str.substr(0, 16);
	var data = str.substr(16);
	var decrypted = CryptoJS.AES.decrypt(data, key, {
		iv: CryptoJS.enc.Utf8.parse(iv),
		format: CryptoJS.format.OpenSSL
	});
	return decrypted.toString(CryptoJS.enc.Utf8);
}
//获取当前APP操作系统类型
var device_type;
if(mui.os.android) {
	device_type = "android";
} else {
	if(mui.os.ios) {
		device_type = "ios";
	} else {
		device_type = "other";
	}
}
//   当前APP操作系统版本
var device_version = mui.os.version;
// var device_model=puls.device.model;

/**
 * 默认客服电话 
 */
var default_kefu = '4008001006';
/**
 *序列化表单，主要用于提交数据 
 * @param {Object} form
 */
function formser(form) {
	var form = document.getElementById(form);
	var arr = {};
	for(var i = 0; i < form.elements.length; i++) {
		var feled = form.elements[i];
		switch(feled.type) {
			case undefined:
			case 'button':
			case 'file':
			case 'reset':
			case 'submit':
				break;
			case 'checkbox':
			case 'radio':
				if(!feled.checked) {
					break;
				}
			default:
				if(arr[feled.name]) {
					arr[feled.name] = arr[feled.name] + ',' + feled.value;
				} else {
					arr[feled.name] = feled.value;

				}
		}
	}
	return arr
}

/**
 *
 * 判断是否登录，如果登录，则返回用户信息,否则强制跳转到登录页面
 * 
 */
function typeUpdate() {
	var path;
	if(baseurl == 'didi.91xinxiang.com'){
		path = 'http://didi.91xinxiang.com/last.apk';
	}else{
	 	path = 'http://didi.test.91xinxiang.com/last.apk';
	}
	//正式
//	var path = 'http://didi.91xinxiang.com/last.apk';
	//	测试
	//	var path = 'http://didi.test.91xinxiang.com/last.apk';
	var ver;
	//休眠方法
	function sleep(numberMillis) {
		var now = new Date();
		var exitTime = now.getTime() + numberMillis;
		while(true) {
			now = new Date();
			if(now.getTime() > exitTime)
				return;
		}
	}

	//判断是否是最新版本
	ajaxGet('common/check_version.html', {
		version: app_version
	}, function(res) {
		console.log("res:" + JSON.stringify(res));
		if(res.code == 1) {
			//是最新版本 不需要更新
		} else if(res.code == 0) {
			var ua = navigator.userAgent.toLowerCase();
			var totalSize = res.data.size;
			if(/iphone|ipad|ipod/.test(ua)) {
				mui.confirm('发现新版本，请您到苹果商店进行下载！', '温馨提示！', ['取消', '确定'], function(e) {
					if(e.index == 1) {
						plus.runtime.openURL('https://itunes.apple.com/us/app/%E6%BB%B4%E6%BB%B4%E5%BF%AB%E9%80%81/id1315938865?l=zh&ls=1&mt=8', function() {
							mui.toast('系统繁忙，请稍后再试');
						})
					}
				})
			} else if(/android/.test(ua)) {
				var btnArray = ['是', '否'];
				mui.confirm('最新version是：' + res.data.app_version + ' ,是否更新', '发现最新版本', btnArray, function(z) {
					if(z.index == 0) {
						plus.runtime.openURL(path, function() {
							mui.toast('系统繁忙，请稍后再试');
						})
//						console.log('确定');
//						var mask = mui.createMask();
//						mask.show();
//						var progressbar = document.getElementById("progressbar");
//						progressbar.style.display = 'block';
//						var dtask = plus.downloader.createDownload(path, {}, function(d, status) {
//							if(status == 200) {
//								//                clearInterval(i);
//								mui('#progress').progressbar().setProgress(100);
//								setTimeout(function() {
//									progressbar.style.display = 'none';
//									mask.close();
//								}, 1000);
//								console.log('下载成功')
//								plus.nativeUI.toast("正在准备环境，请稍后！");
//								sleep(1000);
//								var path = d.filename; //_downloads yijietong.apk
//								console.log(d.filename);
//								plus.runtime.install(path); // 安装下载的apk文件
//							} else {
//								alert('Download failed:' + status);
//							}
//						});
//						dtask.start();
//						//						mui("#progress").progressbar({progress:0}).show();
//						dtask.addEventListener("statechanged", function(task, status) {
//							switch(task.state) {
//								case 3:
//									var a = parseInt(task.downloadedSize / totalSize * 100);
//									mui('#progress').progressbar().setProgress(a);
//									break;
//							}
//						});
					} else {
						console.log('不确定');
						return;
					}
				});
			}
		}
	}, function(res) {
		console.log("shibai");
	}, true)
}

function is_login() {
	var userinfo = localStorage.getItem('userinfo');
	if(userinfo == null) {
		//		mui.confirm('', '您还未登录', ['现在去登录'], function(res) {
		//			mui.openWindow({
		//				id: 'login_code.html',
		//				url: '/login_code.html'
		//			});
		//
		//		}, 'div')
		return false;
	} else {
		return JSON.parse(userinfo);
	}
}

/**
 * 退出登录
 */
function logout() {
	localStorage.removeItem("userinfo");
	//清除token
	localStorage.removeItem("access_token");
	mui.openWindow({
		id: "/login_code.html",
		url: "/login_code.html"
	})
}

/**
 * 更新用户信息 
 */
function setUserInfo(userinfo) {
	localStorage.setItem("userinfo", userinfo);
}

//判断是否登录
function isLogin(owner, id) {
	if(owner) {
		mui.openWindow({
			id: id,
			url: id
			//			createNew:true
		})
	} else {
		mui.confirm('', '您还未登录，请先登录', ['我知道了', '现在去登录'], function(res) {
			if(res.index == 1) {
				mui.openWindow({
					id: "login_code.html",
					url: "/login_code.html"
				})
			}
		}, 'div');
	}
}

function G(id) {
	return document.getElementById(id);
}

//mui ajax封装
function checkAjaxData(res) {
	var times = new Date().getTime();
	if(!res.sign) {
		return false;
	}
	var string = decrypt(res.sign);
	var json = eval("(" + string + ")");
	if(json.timestamp != res.timestamp) {
		mui.alert("请求数据错误");
		return false;
	} else
	if(res.timestamp - times > 50 * 60 * 1000) {
		mui.alert("请求数据超时");
		return false;
	} else {
		return true;
	}
}

var mask = mui.createMask(); //遮罩层
function ajaxRequest(url, params, success, error, loading, type, async) {
	//true 不加载 默认false 加载
	var load = loading || false;
	//实际访问的URL
	var fullurl = siteurl + "/api/" + api_version + "/" + url;
	if(siteurl == 'http://didi.51zhcs.com') {
		mui.toast('这是测试服 这是1.09');
	}
	console.log(fullurl);
	//获取token
	var token = localStorage.getItem("access_token");
	var areaid = localStorage.getItem("areaid");
	//	生成时间戳
	var timestamp = new Date().getTime();
	//组装头 
	var headers = {
		'areaid': areaid,
		'version': app_version,
		'timestamp': timestamp,
		'accesstoken': token,
		'devicetype': device_type,
		'deviceversion': device_version
	};
	var geolocation = new BMap.Geolocation();
	geolocation.getCurrentPosition(function(r) {
		if(this.getStatus() == BMAP_STATUS_SUCCESS) {
			localStorage.setItem('lat', r.point.lat);
			localStorage.setItem('lng', r.point.lng);
		} else {
			mui.toast('定位失败');
		}
	});
	var headerLat = localStorage.getItem('lat');
	var headerLng = localStorage.getItem('lng');
	if(typeof headerLat != 'undefined' && typeof headerLng != 'undefined') {
		headers.lat = headerLat;
		headers.lng = headerLng;
	}
	getInfo();

	function getInfo() {
		console.log("定时获取header:" + JSON.stringify(headers));
		//把头对象转变为json对象
		var json = JSON.stringify(headers);
		//对header进行加密
		headers.sign = encrypt(json);
		async = async ? async : false;
		console.log("async:" + async);
		mui.ajax(fullurl, {
			data: params,
			type: type,
			dataType: "json",
			async: async,
			headers: headers,
			success: function(res) {
				//				if(res.code == -1 || res.code == -2) {
				//					console.log('执行了这里');
				//					mui.confirm('', "你还没有登录请登录", ['现在去登录'], function(res) {
				//						console.log('关闭了页面');
				//						mui.openWindow({
				//							id: 'login_code.html',
				//							url: '/login_code.html'
				//						});
				//					}, 'div');
				//				}
				if(false != checkAjaxData(res)) {
					success(res);
				}
			},
			error: function(data) {
				console.log("error111" + JSON.stringify(data));
				if(data.code == 0) {
					mui.toast(data.msg);
				}
				if(data.statusText) {
					if(data.response) {
						var a = eval("(" + data.response + ")");
						if(a.code == -1 || a.code == -2) {
							mui.confirm('', "你还没有登录请登录", ['现在去登录'], function(res) {
								mui.openWindow({
									id: 'login_code.html',
									url: '/login_code.html'
								});
							}, 'div');
							return false;
						}
					}
				}
				error(data);
			},
			beforeSend: function() {
				if(!load) {
					plus.nativeUI.showWaiting();
					mask.show(); //显示遮罩层
				} else {
					//不显示加载
				}

			},
			complete: function() {
				if(!load) {
					plus.nativeUI.closeWaiting();
					mask.close(); //关闭遮罩层
				} else {
					//不显示加载
				}

			}
		});
	}

}

function ajaxPost(url, params, success, error, load, async) {
	ajaxRequest(url, params, success, error, load, "post", async);
}

function ajaxGet(url, params, success, error, load, async) {
	ajaxRequest(url, params, success, error, load, "get", async);
}
//vue获取数据
function vue_ajax(url, params, success, error, lng, lat, async, type) {
	//实际访问的URL
	var fullurl = siteurl + "/api/" + api_version + "/" + url;
	if(siteurl == 'http://didi.51zhcs.com') {
		mui.toast('这是测试服 这是1.09');
	};
	var token = localStorage.getItem('access_token');
	//	城市code
	var areaid = localStorage.getItem('areaid');
	//生成时间戳
	var timestamp = new Date().getTime();
	var headers = {
		areaid: areaid,
		version: app_version,
		timestamp: timestamp,
		accesstoken: token,
		devicetype: device_type, //当前操作系统
		deviceversion: device_version, //
		lat: lat,
		lng: lng
	}
	var header_json = JSON.stringify(headers);
	console.log('头数据:' + header_json);
	headers.sign = encrypt(header_json);
	var async = async ? async : false;
	mui.ajax(fullurl, {
		data: params,
		dataType: 'json',
		headers: headers,
		async: async,
		success: success,
		error: error
	});
}

function vue_ajaxGet(url, params, success, error, async, lng, lat, type) {
	vue_ajax(url, params, success, error, async, lng, lat, "get");
}

function vue_ajaxPost(url, params, success, error, async, lng, lat, type) {
	vue_ajax(url, params, success, error, async, lng, lat, "post");
}

//百度地图API 获取当前所在经纬度
function get_point() {
	var g = window.navigator.geolocation;
	g.getCurrentPosition(succCallback, errCallback);
	var res = new Array();
	//定位成功后的回调函数
	function succCallback(position) {
		res.push(1);
		res.push(position.coords.longitude);
		res.push(position.coords.latitude);

	}
	//定位失败后的回调函数
	function errCallback(err) {
		res.push(0);
	}
	return res;
}

/**
 * 播放音频
 * @param {Object} path
 * */

function playAudio(path) {
	console.log('aa');
	var player = plus.audio.createPlayer(path);
	player.play(function() {
		mui.toast("播放成功");
	}, function(e) {
		mui.toast('播放失败');
	});
}


/**
 * base64字符串转成语音文件(参考http://ask.dcloud.net.cn/question/16935)
 * @param {Object} base64Str
 * @param {Object} callback
 */
function dataURL2Audio(base64Str, callback) {
	var base64Str = base64Str.replace('data:audio/amr;base64,', '');
	var audioName = "_doc/audio/"+(new Date()).valueOf() + '.amr';
	plus.io.requestFileSystem(plus.io.PRIVATE_DOC, function(fs) {
		fs.root.getFile(audioName, {
			create: true
		}, function(entry) {
			// 获得平台绝对路径
			var fullPath = entry.fullPath;
			console.log("fullPath:"+fullPath);
			if(mui.os.android) {
				console.log('1111');
				// 读取音频
				var Base64 = plus.android.importClass("android.util.Base64");
				var FileOutputStream = plus.android.importClass("java.io.FileOutputStream");
				try {
					var out = new FileOutputStream(fullPath);
					var bytes = Base64.decode(base64Str, Base64.DEFAULT);
					out.write(bytes);
					out.close();
					// 回调
					callback && callback(entry);
				} catch(e) {
					console.log(e.message);
				}
			} else if(mui.os.ios) {
				var NSData = plus.ios.importClass('NSData');
				var nsData = new NSData();
				nsData = nsData.initWithBase64EncodedStringoptions(base64Str, 0);
				if(nsData) {
					nsData.plusCallMethod({
						writeToFile: fullPath,
						atomically: true
					});
					plus.ios.deleteObject(nsData);
				}
				// 回调
				callback && callback(entry);
			}
		})
	})
}

//压缩图片转成base64

function getBase64Image(img, maxwidth) {
	var canvas = document.createElement("canvas");
	var width = img.width;
	var height = img.height;
	if(width > height) {
		if(width > maxwidth) {
			height = Math.round(height *= maxwidth / width);
			width = maxwidth;
		}
	} else {
		if(height > maxwidth) {
			width = Math.round(width *= maxwidth / height);
		}
		height = maxwidth;
	}
	canvas.width = width;
	canvas.height = height;
	var ctx = canvas.getContext('2d');
	ctx.drawImage(img, 0, 0, width, height);
	var dataUrl = canvas.toDataURL('image/png', 0.8);
	return dataUrl.replace('data:image/png:base64', '');
}

