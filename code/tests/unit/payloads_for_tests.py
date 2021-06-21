EXPECTED_RESPONSE_OF_JWKS_ENDPOINT = {
  'keys': [
    {
      'kty': 'RSA',
      'n': 'tSKfSeI0fukRIX38AHlKB1YPpX8PUYN2JdvfM-XjNmLfU1M74N0V'
           'mdzIX95sneQGO9kC2xMIE-AIlt52Yf_KgBZggAlS9Y0Vx8DsSL2H'
           'vOjguAdXir3vYLvAyyHin_mUisJOqccFKChHKjnk0uXy_38-1r17'
           '_cYTp76brKpU1I4kM20M__dbvLBWjfzyw9ehufr74aVwr-0xJfsB'
           'Vr2oaQFww_XHGz69Q7yHK6DbxYO4w4q2sIfcC4pT8XTPHo4JZ2M7'
           '33Ea8a7HxtZS563_mhhRZLU5aynQpwaVv2U--CL6EvGt8TlNZOke'
           'Rv8wz-Rt8B70jzoRpVK36rR-pHKlXhMGT619v82LneTdsqA25Wi2'
           'Ld_c0niuul24A6-aaj2u9SWbxA9LmVtFntvNbRaHXE1SLpLPoIp8'
           'uppGF02Nz2v3ld8gCnTTWfq_BQ80Qy8e0coRRABECZrjIMzHEg6M'
           'loRDy4na0pRQv61VogqRKDU2r3_VezFPQDb3ciYsZjWBr3HpNOkU'
           'jTrvLmFyOE9Q5R_qQGmc6BYtfk5rn7iIfXlkJAZHXhBy-ElBuiBM'
           '-YSkFM7dH92sSIoZ05V4MP09Xcppx7kdwsJy72Sust9Hnd9B7V35'
           'YnVF6W791lVHnenhCJOziRmkH4xLLbPkaST2Ks3IHH7tVltM6NsR'
           'k3jNdVM',
      'e': 'AQAB',
      'alg': 'RS256',
      'kid': '02B1174234C29F8EFB69911438F597FF3FFEE6B7',
      'use': 'sig'
    }
  ]
}

RESPONSE_OF_JWKS_ENDPOINT_WITH_WRONG_KEY = {
    'keys': [
        {
            'kty': 'RSA',
            'n': 'pSKfSeI0fukRIX38AHlKB1YPpX8PUYN2JdvfM-XjNmLfU1M74N0V'
                 'mdzIX95sneQGO9kC2xMIE-AIlt52Yf_KgBZggAlS9Y0Vx8DsSL2H'
                 'vOjguAdXir3vYLvAyyHin_mUisJOqccFKChHKjnk0uXy_38-1r17'
                 '_cYTp76brKpU1I4kM20M__dbvLBWjfzyw9ehufr74aVwr-0xJfsB'
                 'Vr2oaQFww_XHGz69Q7yHK6DbxYO4w4q2sIfcC4pT8XTPHo4JZ2M7'
                 '33Ea8a7HxtZS563_mhhRZLU5aynQpwaVv2U--CL6EvGt8TlNZOke'
                 'Rv8wz-Rt8B70jzoRpVK36rR-pHKlXhMGT619v82LneTdsqA25Wi2'
                 'Ld_c0niuul24A6-aaj2u9SWbxA9LmVtFntvNbRaHXE1SLpLPoIp8'
                 'uppGF02Nz2v3ld8gCnTTWfq_BQ80Qy8e0coRRABECZrjIMzHEg6M'
                 'loRDy4na0pRQv61VogqRKDU2r3_VezFPQDb3ciYsZjWBr3HpNOkU'
                 'jTrvLmFyOE9Q5R_qQGmc6BYtfk5rn7iIfXlkJAZHXhBy-ElBuiBM'
                 '-YSkFM7dH92sSIoZ05V4MP09Xcppx7kdwsJy72Sust9Hnd9B7V35'
                 'YnVF6W791lVHnenhCJOziRmkH4xLLbPkaST2Ks3IHH7tVltM6NsR'
                 'k3jNdVM',
            'e': 'AQAB',
            'alg': 'RS256',
            'kid': '02B1174234C29F8EFB69911438F597FF3FFEE6B7',
            'use': 'sig'
        }
    ]
}

PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----"""

EXPECTED_RESPONSE_FROM_RECORDED_FUTURE = {
    "data": {
        "timestamps": {
            "lastSeen": "2021-06-21T07:26:43.277Z",
            "firstSeen": "2009-05-26T12:15:30.000Z"
        },
        "risk": {
            "criticalityLabel": "Unusual",
            "riskString": "2/44",
            "rules": 2,
            "criticality": 1,
            "riskSummary": "2 of 44 Risk Rules currently observed.",
            "score": 10,
            "evidenceDetails": [
                {
                    "mitigationString": "",
                    "evidenceString": "2 sightings on 1 source: Insikt Group."
                                      " 2 reports including Partial List of D"
                                      "ecoded Domains Linked to SUNBURST C2 C"
                                      "ommunications. Most recent link (Dec 22"
                                      ", 2020): https://app.recordedfuture.com"
                                      "/live/sc/52qYMuHmYqU1",
                    "rule": "Historically Referenced by Insikt Group",
                    "criticality": 1,
                    "timestamp": "2020-12-22T00:00:00.000Z",
                    "criticalityLabel": "Unusual"
                },
                {
                    "mitigationString": "",
                    "evidenceString": "1 sighting on 1 source: Recorded Future"
                                      " Analyst Community Trending Indicators."
                                      " Recently viewed by many analysts in ma"
                                      "ny organizations in the Recorded Future"
                                      " community.",
                    "rule": "Trending in Recorded Future Analyst Community",
                    "criticality": 1,
                    "timestamp": "2021-06-21T07:33:00.061Z",
                    "criticalityLabel": "Unusual"
                }
            ]
        },
        "intelCard": "https://app.recordedfuture.com/live/sc/entity/idn%3A"
                     "cisco.com",
        "sightings": [
            {
                "source": "Fast Company",
                "url": "http://feedproxy.google.com/~r/fastcompany/headlines"
                       "/~3/2lG8pHrMDbA/1279087",
                "published": "2009-05-26T13:00:23.000Z",
                "fragment": "\"Market transition\" may be a charming euphemism"
                            " for meltdown, but Cisco's real transition has "
                            "been to use technology to connect with prospects,"
                            " turbocharging Cisco.com from an expert resource "
                            "for about 15 million visitors a month into a lead"
                            "-generation engine of real power.",
                "title": "How Big Business Weathers the Economic Storm",
                "type": "first"
            },
            {
                "source": "GitHub",
                "url": "https://github.com/TheXPerienceProject/android_kernel_"
                       "xiaomi_vayu/blob/master/Documentation/translations/"
                       "zh_CN/HOWTO",
                "published": "2021-06-21T07:04:30.000Z",
                "fragment": "HOWTO , Roland Dreier <rolandd@cisco.com> git."
                            "kernel.org:/pub/scm/linux/kernel/git/roland/"
                            "infiniband.git",
                "title": "HOWTO",
                "type": "mostRecent"
            },
            {
                "source": "Russian Market",
                "url": "http://Russian%20Market%20(Obfuscated)/logs?stealer=&s"
                       "ystem=&country=&state=&city=&zip=&page=235&perpage=50&"
                       "isp=&outlook=&links=&withcookies=0&pricesort=&priceran"
                       "ge=0;10&vendor=#ebad6be806b2d911351bc34793d9ae7e",
                "published": "2021-06-16T21:55:56.166Z",
                "fragment": "| signin.ebay.es | dvdbarato.net | twikiteros.com"
                            " | intercambiosvirtuales.org | subtel.es | world-"
                            "driver.com | x-caleta.com | cablematic.com | pord"
                            "escargadirecta.com | 192.168.68.1 | microcubo.com"
                            " | octilus.com | ftworld.com | es.eetgroup.com | "
                            "esprinet.com | miui.es | foro.el-hacker.com | fre"
                            "ecovers.net | gsmspain.com | bankoanet.com | m.fa"
                            "cebook.com | secure.avangate.com | e-nuc.com | sy"
                            "nc.xmarks.com | ver.movistarplus.es | captchatrad"
                            "er.com | webmail.tekno2000.com | sitioseguro.movi"
                            "starplus.es | sicv3.chs.com.es | esprinet.com | u"
                            "niversodivx.net | hackingxtreme.net | my.kaspersk"
                            "y.com | juegos.loteriasyapuestas.es | globomatik."
                            "com | cerberusapp.com | mail.internationalcombust"
                            "ion.in | freecovers.net | gratisprogramas.bligoo."
                            "com | universodivx.net | 2.139.110.34 | 4shared.c"
                            "om | gratispeliculas.org | 192.168.1.1 | juegos.l"
                            "oteriasyapuestas.es | es.ingrammicro.com | e-nuc."
                            "com | 192.168.1.1 | vinzeo.com | peliculaswarez.c"
                            "om | paypal.com | uploading.com | universodivx.ne"
                            "t | bdpcenter.com | ",
                "title": "Russian Market",
                "type": "recentDarkWeb"
            },
            {
                "source": "GitHub",
                "url": "https://github.com/TheXPerienceProject/android_kernel_"
                       "xiaomi_vayu/blob/master/Documentation/translations/zh_"
                       "CN/HOWTO",
                "published": "2021-06-21T07:04:30.000Z",
                "fragment": "HOWTO , Roland Dreier <rolandd@cisco.com> git.ker"
                            "nel.org:/pub/scm/linux/kernel/git/roland/infiniba"
                            "nd.git",
                "title": "HOWTO",
                "type": "recentInfoSec"
            },
            {
                "source": "PasteBin",
                "url": "https://pastebin.com/s9dGSuMH",
                "published": "2021-06-16T10:07:26.000Z",
                "fragment": "*.cisco.com, *.webex.com, localhost, 127.0.0.0/8,"
                            " ::1, 10.",
                "title": "Untitled Paste from Pastebin",
                "type": "recentPaste"
            }
        ],
        "entity": {
            "id": "idn:cisco.com",
            "name": "cisco.com",
            "type": "InternetDomainName"
        }
    }
}
