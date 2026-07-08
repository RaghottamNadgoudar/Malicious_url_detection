"""
trusted_suffixes.py
===================
Machine-generated from the Mozilla Public Suffix List (PSL):
  https://publicsuffix.org/list/public_suffix_list.dat

Contains ALL government (gov.*), academic (ac.*, edu.*),
military (mil.*), school (sch.*), and restricted (res.*) suffixes
plus the IANA-sponsored global TLDs: edu, gov, mil, int.

These domains are structurally RESTRICTED — only legitimate institutions
can register under them — so any URL with these suffixes is treated as
SAFE (Tier 1 whitelist) unless another hard signal overrides it.

Generated: 2026-07-08  |  PSL version used: live
"""

TRUSTED_SUFFIXES: frozenset = frozenset({
    # ── IANA Sponsored (global, fully restricted) ─────────────────────────────
    'edu', 'gov', 'mil', 'int',

    # ── Academic (ac.*) ───────────────────────────────────────────────────────
    'ac.ae','ac.at','ac.bd','ac.be','ac.bw','ac.ci','ac.cn','ac.cr',
    'ac.cy','ac.eg','ac.fj','ac.gn','ac.gov.br','ac.id','ac.il','ac.im',
    'ac.in','ac.ir','ac.jp','ac.ke','ac.kr','ac.leg.br','ac.lk','ac.ls',
    'ac.ma','ac.me','ac.ml','ac.mu','ac.mw','ac.mz','ac.ni','ac.nz',
    'ac.pa','ac.pk','ac.pr','ac.rs','ac.ru','ac.rw','ac.se','ac.sz',
    'ac.th','ac.tj','ac.tz','ac.ug','ac.uk','ac.vn','ac.za','ac.zm','ac.zw',

    # ── Education (edu.*) ─────────────────────────────────────────────────────
    'edu.ac','edu.af','edu.al','edu.ao','edu.ar','edu.au','edu.az',
    'edu.ba','edu.bb','edu.bd','edu.bh','edu.bi','edu.bj','edu.bm',
    'edu.bn','edu.bo','edu.br','edu.bs','edu.bt','edu.bz','edu.ci',
    'edu.cn','edu.co','edu.cu','edu.cv','edu.cw','edu.dm','edu.do',
    'edu.dz','edu.ec','edu.ee','edu.eg','edu.es','edu.et','edu.eu.org',
    'edu.fj','edu.fm','edu.gd','edu.ge','edu.gh','edu.gi','edu.gl',
    'edu.gn','edu.gp','edu.gr','edu.gt','edu.gu','edu.gy','edu.hk',
    'edu.hn','edu.ht','edu.in','edu.io','edu.iq','edu.it','edu.jo',
    'edu.kg','edu.kh','edu.ki','edu.km','edu.kn','edu.kp','edu.krd',
    'edu.kw','edu.ky','edu.kz','edu.la','edu.lb','edu.lc','edu.lk',
    'edu.lr','edu.ls','edu.lv','edu.ly','edu.me','edu.mg','edu.mk',
    'edu.ml','edu.mn','edu.mo','edu.ms','edu.mt','edu.mv','edu.mw',
    'edu.mx','edu.my','edu.mz','edu.ng','edu.ni','edu.nr','edu.om',
    'edu.pa','edu.pe','edu.pf','edu.ph','edu.pk','edu.pl','edu.pn',
    'edu.pr','edu.ps','edu.pt','edu.py','edu.qa','edu.rs','edu.ru',
    'edu.sa','edu.sb','edu.sc','edu.sd','edu.sg','edu.sl','edu.sn',
    'edu.so','edu.ss','edu.st','edu.sv','edu.sy','edu.tj','edu.tm',
    'edu.to','edu.tr','edu.tt','edu.tw','edu.ua','edu.ug','edu.uy',
    'edu.vc','edu.ve','edu.vg','edu.vn','edu.vu','edu.ws','edu.ye',
    'edu.za','edu.zm',

    # ── Government (gov.*) ───────────────────────────────────────────────────
    'gov.ac','gov.ae','gov.af','gov.al','gov.ao','gov.ar','gov.as',
    'gov.au','gov.az','gov.ba','gov.bb','gov.bd','gov.bf','gov.bh',
    'gov.bm','gov.bn','gov.br','gov.bs','gov.bt','gov.bw','gov.by',
    'gov.bz','gov.cd','gov.cl','gov.cm','gov.cn','gov.co','gov.cx',
    'gov.cy','gov.cz','gov.dm','gov.do','gov.dz','gov.ec','gov.ee',
    'gov.eg','gov.et','gov.fj','gov.gd','gov.ge','gov.gh','gov.gi',
    'gov.gn','gov.gr','gov.gu','gov.gy','gov.hk','gov.ie','gov.il',
    'gov.in','gov.io','gov.iq','gov.ir','gov.it','gov.jo','gov.kg',
    'gov.kh','gov.ki','gov.km','gov.kn','gov.kp','gov.kw','gov.kz',
    'gov.la','gov.lb','gov.lc','gov.lk','gov.lr','gov.ls','gov.lt',
    'gov.lv','gov.ly','gov.ma','gov.me','gov.mg','gov.mk','gov.ml',
    'gov.mn','gov.mo','gov.mr','gov.ms','gov.mu','gov.mv','gov.mw',
    'gov.my','gov.mz','gov.na','gov.nc.tr','gov.ng','gov.nl','gov.nr',
    'gov.om','gov.ph','gov.pk','gov.pl','gov.pn','gov.pr','gov.ps',
    'gov.pt','gov.pw','gov.py','gov.qa','gov.rs','gov.ru','gov.rw',
    'gov.sa','gov.sb','gov.sc','gov.scot','gov.sd','gov.sg','gov.sh',
    'gov.sl','gov.so','gov.ss','gov.sx','gov.sy','gov.tj','gov.tl',
    'gov.tm','gov.tn','gov.to','gov.tr','gov.tt','gov.tw','gov.ua',
    'gov.ug','gov.uk','gov.vc','gov.ve','gov.vn','gov.ws','gov.ye',
    'gov.za','gov.zm','gov.zw',

    # ── Military (mil.*) ─────────────────────────────────────────────────────
    'mil.ac','mil.ae','mil.al','mil.ar','mil.az','mil.ba','mil.bd',
    'mil.bo','mil.br','mil.by','mil.cl','mil.cn','mil.co','mil.cy',
    'mil.do','mil.ec','mil.eg','mil.fj','mil.gh','mil.gt','mil.hn',
    'mil.id','mil.in','mil.io','mil.iq','mil.jo','mil.kg','mil.km',
    'mil.kr','mil.kz','mil.lv','mil.mg','mil.mv','mil.my','mil.mz',
    'mil.ng','mil.ni','mil.no','mil.nz','mil.pe','mil.ph','mil.pl',
    'mil.py','mil.qa','mil.ru','mil.rw','mil.sh','mil.st','mil.sy',
    'mil.tj','mil.tm','mil.to','mil.tr','mil.tt','mil.tw','mil.tz',
    'mil.ug','mil.uy','mil.vc','mil.ve','mil.ye','mil.za','mil.zm','mil.zw',

    # ── Schools (sch.*) ───────────────────────────────────────────────────────
    'sch.ac','sch.ae','sch.bd','sch.id','sch.ir','sch.jo','sch.lk',
    'sch.ly','sch.ng','sch.qa','sch.sa','sch.ss','sch.tf','sch.wf','sch.zm',

    # ── Research (res.*) ─────────────────────────────────────────────────────
    'res.aero','res.in',
})


def is_trusted_suffix(suffix: str) -> bool:
    """Return True if the PSL suffix is a restricted gov/edu/mil domain."""
    return suffix.lower() in TRUSTED_SUFFIXES
