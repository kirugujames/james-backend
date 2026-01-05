import fs from 'fs';

// Raw data from your table (rows 48-181 show wards with constituencies)
const rawData = `1	1	changamwe	port reitz
2	1	changamwe	kipevu
3	1	changamwe	airport
4	1	changamwe	changamwe
5	1	changamwe	chaani
6	1	jomvu	jomvu kuu
7	1	jomvu	miritini
8	1	jomvu	mikindani
9	1	kisauni	mjambere
10	1	kisauni	junda
11	1	kisauni	bamburi
12	1	kisauni	mwakirunge
13	1	kisauni	mtopanga
14	1	kisauni	magogoni
15	1	kisauni	shanzu
16	1	nyali	frere town
17	1	nyali	ziwa la ng'ombe
18	1	nyali	mkomani
19	1	nyali	kongowea
20	1	nyali	kadzandani
21	1	likoni	mtongwe
22	1	likoni	shika adabu
23	1	likoni	bofu
24	1	likoni	likoni
25	1	likoni	timbwani
26	1	mvita	mji wa kale/makadara
27	1	mvita	tudor
28	1	mvita	tononoka
29	1	mvita	shimanzi/ganjoni
30	1	mvita	majengo
31	2	msambweni	gombatobongwe
32	2	msambweni	ukunda
33	2	msambweni	kinondo
34	2	msambweni	ramisi
35	2	lungalunga	pongwekikoneni
36	2	lungalunga	dzombo
37	2	lungalunga	mwereni
38	2	lungalunga	vanga
39	2	matuga	tsimba golini
40	2	matuga	waa
41	2	matuga	tiwi
42	2	matuga	kubo south
43	2	matuga	mkongani
44	2	kinango	nadavaya
45	2	kinango	puma
46	2	kinango	kinango
47	2	kinango	mackinnon-road
48	2	kinango	chengoni/samburu
49	2	kinango	mwavumbo
50	2	kinango	kasemeni
51	3	kilifi north	tezo
52	3	kilifi north	sokoni
53	3	kilifi north	kibarani
54	3	kilifi north	dabaso
55	3	kilifi north	matsangoni
56	3	kilifi north	watamu
57	3	kilifi north	mnarani
58	3	kilifi south	junju
59	3	kilifi south	mwarakaya
60	3	kilifi south	shimo la tewa
61	3	kilifi south	chasimba
62	3	kilifi south	mtepeni
63	3	kaloleni	mariakani
64	3	kaloleni	kayafungo
65	3	kaloleni	kaloleni
66	3	kaloleni	mwanamwinga
67	3	rabai	mwawesa
68	3	rabai	ruruma
69	3	rabai	kambe/ribe
70	3	rabai	rabai/kisurutini
71	3	ganze	ganze
72	3	ganze	bamba
73	3	ganze	jaribuni
74	3	ganze	sokoke
75	3	malindi	jilore
76	3	malindi	kakuyuni
77	3	malindi	ganda
78	3	malindi	malindi town
79	3	malindi	shella
80	3	magarini	marafa
81	3	magarini	magarini
82	3	magarini	gongoni
83	3	magarini	adu
84	3	magarini	garashi
85	3	magarini	sabaki
86	4	garsen	kipini east
87	4	garsen	garsen south
88	4	garsen	kipini west
89	4	garsen	garsen central
90	4	garsen	garsen west
91	4	garsen	garsen north
92	4	galole	kinakomba
93	4	galole	mikinduni
94	4	galole	chewani
95	4	galole	wayu
96	4	bura	chewele
97	4	bura	bura
98	4	bura	bangale
99	4	bura	sala
100	4	bura	madogo
101	5	lamu east	faza
102	5	lamu east	kiunga
103	5	lamu east	basuba
104	5	lamu west	shella
105	5	lamu west	mkomani
106	5	lamu west	hindi
107	5	lamu west	mkunumbi
108	5	lamu west	hongwe
109	5	lamu west	witu
110	5	lamu west	bahari
111	6	taveta	chala
112	6	taveta	mahoo
113	6	taveta	bomeni
114	6	taveta	mboghoni
115	6	taveta	mata
116	6	wundanyi	wundanyi/mbale
117	6	wundanyi	werugha
118	6	wundanyi	wumingu/kishushe
119	6	wundanyi	mwanda/mgange
120	6	mwatate	rong'e
121	6	mwatate	mwatate
122	6	mwatate	bura
123	6	mwatate	chawia
124	6	mwatate	wusi/kishamba
125	6	voi	mbololo
126	6	voi	sagalla
127	6	voi	kaloleni
128	6	voi	marungu
129	6	voi	kasigau
130	6	voi	ngolia
131	7	garissa township	waberi
132	7	garissa township	galbet
133	7	garissa township	township
134	7	garissa township	iftin
135	7	balambala	balambala
136	7	balambala	danyere
137	7	balambala	jara jara
138	7	balambala	saka
139	7	balambala	sankuri
140	7	lagdera	modogashe
141	7	lagdera	benane
142	7	lagdera	goreale
143	7	lagdera	maalimin
144	7	lagdera	sabena
145	7	lagdera	baraki
146	7	dadaab	dertu
147	7	dadaab	dadaab
148	7	dadaab	labasigale
149	7	dadaab	damajale
150	7	dadaab	liboi
151	7	dadaab	abakaile
152	7	fafi	bura
153	7	fafi	dekaharia
154	7	fafi	jarajila
155	7	fafi	fafi
156	7	fafi	nanighi
157	7	ijara	hulugho
158	7	ijara	sangailu
159	7	ijara	ijara
160	7	ijara	masalani
161	8	wajir north	gurar
162	8	wajir north	bute
163	8	wajir north	korondile
164	8	wajir north	malkagufu
165	8	wajir north	batalu
166	8	wajir north	danaba
167	8	wajir north	godoma
168	8	wajir east	wagberi
169	8	wajir east	township
170	8	wajir east	barwago
171	8	wajir east	khorof/harar
172	8	tarbaj	elben
173	8	tarbaj	sarman
174	8	tarbaj	tarbaj
175	8	tarbaj	wargadud
176	8	wajir west	arbajahan
177	8	wajir west	hadado/athibohol
178	8	wajir west	ademasajide
179	8	wajir west	wagalla/ganyure
180	8	eldas	eldas
181	8	eldas	della`;

// Parse the data
const lines = rawData.split('\n');
const constituencies = new Map();
const constituencyIdMap = new Map(); // constituency_name -> auto_increment_id

lines.forEach(line => {
    const parts = line.split('\t').map(p => p.trim());
    const [wardId, countyId, constituencyName, wardName] = parts;

    if (!constituencies.has(constituencyName)) {
        constituencies.set(constituencyName, {
            name: constituencyName,
            county_id: parseInt(countyId),
            wards: []
        });
    }

    constituencies.get(constituencyName).wards.push(wardName);
});

// Generate subcounties JSON
const subcountiesData = {
    subcounties: Array.from(constituencies.values()).map(c => ({
        name: c.name,
        county_id: c.county_id
    }))
};

// Save subcounties to file
fs.writeFileSync(
    './locations/data/subcounties-partial.json',
    JSON.stringify(subcountiesData, null, 2)
);

console.log(`✅ Created subcounties-partial.json with ${subcountiesData.subcounties.length} constituencies`);
console.log('\n📋 Next steps:');
console.log('1. Insert counties first using counties.json');
console.log('2. Insert subcounties using subcounties-partial.json');
console.log('3. After inserting subcounties, get their IDs from the database');
console.log('4. Then I can help you create the wards JSON with proper subcounty_id references');
console.log('\n⚠️  Note: This is partial data (counties 1-8 only). You need the complete dataset for all 47 counties.');
