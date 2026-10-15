"""RFC 8949 examples, malformed input, and independent exhaustive-offset checks."""
import math
import random
import unittest

from cbor_codec import CBORError, Decoder, analyze, decode_input

# RFC 8949 Appendix A (https://www.rfc-editor.org/rfc/rfc8949.html#appendix-A).
# f818 from older RFC 7049 vector collections is deliberately NOT a valid item.
VECTORS = '''
00 01 0a 17 1818 1819 1864 1903e8 1a000f4240 1b000000e8d4a51000
1bffffffffffffffff c249010000000000000000 3bffffffffffffffff c349010000000000000000
20 29 3863 3903e7 f90000 f98000 f93c00 fb3ff199999999999a f93e00 f97bff
fa47c35000 fa7f7fffff fb7e37e43c8800759c f90001 f90400 f9c400 fbc010666666666666
f97c00 f97e00 f9fc00 fa7f800000 fa7fc00000 faff800000 fb7ff0000000000000
fb7ff8000000000000 fbfff0000000000000 f4 f5 f6 f7 f0 f8ff
c074323031332d30332d32315432303a30343a30305a c11a514b67b0 c1fb41d452d9ec200000
d74401020304 d818456449455446 d82076687474703a2f2f7777772e6578616d706c652e636f6d
40 4401020304 60 6161 6449455446 62225c 62c3bc 63e6b0b4 64f0908591
80 83010203 8301820203820405 98190102030405060708090a0b0c0d0e0f101112131415161718181819
a0 a201020304 a26161016162820203 826161a161626163 a56161614161626142616361436164614461656145
5f42010243030405ff 7f657374726561646d696e67ff 9fff 9f018202039f0405ffff
9f01820203820405ff 83018202039f0405ff 83019f0203ff820405 9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff
bf61610161629f0203ffff 826161bf61626163ff bf6346756ef563416d7421ff
'''.split()


def reference(data: bytes, pos: int) -> tuple[int, int]:
    """Small independent recursive wire scanner (no production cache / Node)."""
    if pos >= len(data):
        raise ValueError()
    major, info = data[pos] >> 5, data[pos] & 31
    pos += 1
    if 28 <= info <= 30 or info == 31 and major not in (2, 3, 4, 5):
        raise ValueError()
    value = info
    if 24 <= info <= 27:
        n = 2 ** (info - 24)
        if pos+n > len(data):
            raise ValueError()
        value = int.from_bytes(data[pos:pos+n], 'big')
        pos += n
    if major == 7 and info == 24 and value < 32:
        raise ValueError()
    hits = 1
    if major in (2,3):
        if info == 31:
            while pos < len(data) and data[pos] != 255:
                if data[pos] >> 5 != major or data[pos]&31 == 31:
                    raise ValueError()
                pos,h = reference(data,pos)
                hits += h
            if pos >= len(data):
                raise ValueError()
            pos += 1
        else:
            if pos+value > len(data):
                raise ValueError()
            if major == 3:
                data[pos:pos+value].decode('utf-8')
            pos += value
    elif major in (4,5,6):
        count = 1 if major == 6 else value * (2 if major == 5 else 1)
        seen = 0
        while info == 31 or seen < count:
            if info == 31 and pos < len(data) and data[pos] == 255:
                if major == 5 and seen % 2:
                    raise ValueError()
                pos += 1
                break
            pos,h = reference(data,pos)
            hits += h
            seen += 1
    return pos,hits


class CodecTests(unittest.TestCase):
    def test_rfc_examples(self):
        for hex_data in VECTORS:
            with self.subTest(hex=hex_data):
                raw=bytes.fromhex(hex_data)
                result=analyze(raw,'exact')
                self.assertEqual(result['selected']['end'],len(raw))
                self.assertIsNotNone(result['best'])
                notation=result['selected']['diagnostic']
                rebuilt=decode_input(notation,'diagnostic')
                other=analyze(rebuilt,'exact')
                self.assertEqual(other['selected']['json'],result['selected']['json'])

    def test_exact_offsets_for_nested_types(self):
        raw=bytes.fromhex('ff1ca26161016162820203ff')
        r=analyze(raw)
        self.assertEqual(r['tested'],len(raw))
        self.assertEqual(r['best']['offset'],2)
        self.assertEqual(r['best']['hits'],7)
        self.assertEqual([(x['start'],x['end']) for x in r['selected']['rows']],[(2,11),(3,5),(5,6),(6,8),(8,11),(9,10),(10,11)])

    def test_noise_sample(self):
        raw=b'\xff\x1c\xff\x1c'+decode_input('{"device":"a","values":[1,2,3]}','json')+b'\xff\xff'
        r=analyze(raw)
        self.assertEqual(r['best']['offset'],4)
        self.assertEqual(r['selected']['json'][0]['values'],[1,2,3])
        self.assertFalse(r['selected']['complete'])

    def test_single_vs_sequence(self):
        raw=bytes.fromhex('a1616101a1616102')
        single=analyze(raw)
        self.assertEqual(single['best']['items'],1)
        sequence=analyze(raw,sequence=True)
        self.assertEqual(sequence['best']['items'],2)
        self.assertEqual(sequence['best']['hits'],6)
        self.assertEqual(sequence['best']['offset'],0)

    def test_no_resynchronization_inside_candidate(self):
        result=analyze(bytes.fromhex('0102ff030405'),sequence=True)
        self.assertEqual(result['best']['offset'],3)
        decoder=Decoder(bytes.fromhex('0102ff030405'))
        self.assertEqual(decoder.detail(0,True)['end'],2)
        self.assertEqual(decoder.detail(0,True)['hits'],2)

    def test_tie_breaking(self):
        self.assertEqual(analyze(bytes.fromhex('1818ff1819'))['best']['offset'],0)
        self.assertEqual(analyze(bytes.fromhex('01ff1a00000002'))['best']['offset'],2)

    def test_malformed_inputs(self):
        for h in ['ff','1c','1d','1e','1f','3f','df','f818','f81f','f800','f814','181','18','1901','1a000000','1b00000000000000','43ff','636162','82ff','a101','9f01','bf01ff','5f6161ff','7f4101ff','5f5fffff','62c0af','63eda080','64f4908080']:
            if len(h)%2:
                with self.assertRaises(CBORError):decode_input(h,'hex')
                continue
            with self.subTest(hex=h):
                self.assertNotIn(0,Decoder(bytes.fromhex(h)).nodes)

    def test_empty_and_no_hits(self):
        with self.assertRaises(CBORError): analyze(b'')
        result=analyze(b'\xff\xff')
        self.assertIsNone(result['best'])
        self.assertEqual(result['tested'],2)
        self.assertEqual(result['selected']['rows'],[])

    def test_diagnostic_tags_float_bytes_chunks(self):
        value='{"tag": 999(h\'abcd\'), "float": -0.0_3, "b": b64\'AQID\', "chunks": (_ "a", "b"), "array": [_ 1, 2]}'
        raw=decode_input(value,'diagnostic')
        self.assertIn(bytes.fromhex('fb8000000000000000'),raw)
        self.assertEqual(analyze(raw,'exact')['selected']['json'][0]['b'],{'$bytes':'010203'})

    def test_preserves_nonstring_duplicate_keys(self):
        raw=decode_input('{1: "a", "1": "b", 1: "c", [1,2]: 3}','diagnostic')
        r=analyze(raw,'exact')['selected']
        self.assertEqual(len(r['json'][0]['$map']),4)
        self.assertEqual(len(r['warnings']),1)
        self.assertEqual(len({x['path'] for x in r['rows']}),len(r['rows']))

    def test_64bit_values_not_rounded(self):
        raw=decode_input('[18446744073709551615, -18446744073709551616, 18446744073709551616]','diagnostic')
        r=analyze(raw,'exact')['selected']
        self.assertEqual(r['json'][0][0],{'$integer':'18446744073709551615'})
        self.assertEqual(r['json'][0][1],{'$integer':'-18446744073709551616'})
        self.assertEqual(r['json'][0][2]['$tag'],'2')

    def test_utf8(self):
        raw=decode_input('{"水":"衛星 🚀"}','json')
        self.assertEqual(analyze(raw,'exact')['selected']['json'],[{'水':'衛星 🚀'}])
        self.assertNotIn(0,Decoder(bytes.fromhex('7f61c361bcff')).nodes)

    def test_json_literal_keys(self):
        r=analyze(decode_input('{"$bytes":"0102"}','json'),'exact')
        self.assertEqual(r['selected']['rows'][0]['type'],'map')

    def test_input_validation(self):
        self.assertEqual(decode_input('0x01, 0x02 : 03_04','hex'),b'\x01\x02\x03\x04')
        self.assertEqual(decode_input('AQI','base64'),b'\x01\x02')
        for text,fmt in [('z0','hex'),('0','hex'),('@@','base64'),('NaN','json'),('Infinity','json'),('__import__("os")','diagnostic'),('[1,','diagnostic'),('simple(24)','diagnostic'),('1 trailing','diagnostic'),('"\\ud800"','diagnostic')]:
            with self.subTest(text=text),self.assertRaises(CBORError):decode_input(text,fmt)

    def test_negative_zero_and_nan(self):
        raw=decode_input('[-0.0, NaN, Infinity, -Infinity]','diagnostic')
        r=analyze(raw,'exact')['selected']['json'][0]
        self.assertEqual(math.copysign(1,r[0]),-1)
        self.assertEqual(r[1],{'$float':'NaN'})

    def test_max_depth_is_not_recursion_order_dependent(self):
        d=Decoder(b'\x81'*130+b'\x00')
        self.assertNotIn(0,d.nodes)
        self.assertIn(3,d.nodes)
        self.assertEqual(d.nodes[3].depth,128)

    def test_independent_all_offset_fuzz(self):
        rng=random.Random(8949)
        for sample in range(500):
            data=rng.randbytes(rng.randrange(1,70))
            decoder=Decoder(data)
            expected=[]
            for pos in range(len(data)):
                try:
                    end,hits=reference(data,pos)
                    expected.append((pos,end,hits))
                except (ValueError,UnicodeError,IndexError):
                    pass
            actual=[(p,n.end,n.hits) for p,n in sorted(decoder.nodes.items())]
            self.assertEqual(actual,expected,f'sample {sample} {data.hex()}')
            for sequence in (False,True):
                candidates=[]
                for start,end,hits in expected:
                    items=1
                    if sequence:
                        while end<len(data):
                            try:
                                next_end,h=reference(data,end)
                                hits+=h;items+=1;end=next_end
                            except (ValueError,UnicodeError,IndexError):
                                break
                    candidates.append((start,end,hits,items))
                candidates.sort(key=lambda x:(-x[2],-(x[1]-x[0]),-x[3],x[0]))
                actual=decoder.candidates(sequence=sequence)
                self.assertEqual([(c['offset'],c['end'],c['hits'],c['items']) for c in actual],candidates)


if __name__=='__main__':unittest.main()
