;(function(window, document, undef){

    var dongle;

    /**
     * If already loaded, don't load it again
     */
    if (typeof window.PU !== typeof undef) return;

    /* Convert an interger to its hexadecimal
       representation with proper 0 padding
       If no size given, use size 2 */
    var toHex = function(num, len) {
        if (typeof len == typeof undef) len = 2
        var padding = Array(len).join("0")
        return (padding + num.toString(16)).substr(-len)
    }

    var PU = function() {

        var selectFirst = function() {
            Daplug.getFirstDongle(function(firstDongle){
                dongle = firstDongle
                console.debug("First dongle selected")
            })
        }

        var testApdu = function() {
            dongle.getSerial(function(ans){
                console.debug(ans.toString(HEX))
            })
        }

        function commonAuth(then){
            var ks = new Daplug.KeySet(0x01, "404142434445464748494A4B4C4D4E4F")
            var secu = Daplug.C_MAC //+ Daplug.C_DEC + Daplug.R_MAC + Daplug.R_ENC
            console.debug("Authenticating")
            dongle.authenticate(ks, secu)(then)
        }

        var testAuth = function() {
            commonAuth(function(){
                console.debug("Auth success")
                setTimeout(function(){
                    dongle.getSerial(
                        function(ans){
                            console.debug("Serial: " + ans.toString(HEX))
                            dongle.getSerial(
                                function(ans){
                                    console.debug("Serial: " + ans.toString(HEX))
                                }
                            )
                        }
                    )
                }, 10)
            })
        }

        var testFile = function() {
            var content = "abbe1acceda1accede1accede1baba1baffe1baffee1ba0bab1bebe1b0b01caca1cacaba1cacabe1caca01cade1cafe1ceda1cede1cedee1c0bea1c0ca1c0c01c0da1c0dee1dada1deca1decade1decede1decedee1dec0da1dec0de1dec0dee1d0d01ecaffa1ecaffe1ecaffe1ecaffee1eccaca1efface1effacee1facade1face1faceaface1fada1fade1fadee1fad01abbe1acceda1accede1accede1baba1baffe1baffee1ba0bab1bebe1b0b01caca1cacaba1cacabe1caca01cade1cafe1ceda1cede1cedee1c0bea1c0ca1c0c01c0da1c0dee1dada1deca1decade1decede1decedee1dec0da1dec0de1dec0dee1d0d01ecaffa1ecaffe1ecaffe1ecaffee1eccaca1efface1effacee1facade1face1faceaface1fada1fade1fadee1fad01abbe1acceda1accede1accede1baba1baffe1baffee1ba0bab1bebe1b0b01caca1cacaba1cacabe1caca01cade1cafe1ceda1cede1cedee1c0bea1c0ca1c0c01c0da1c0dee1dada1deca1decade1decede1decedee1dec0da1dec0de1dec0dee1d0d01ecaffa1ecaffe1ecaffe1ecaffee1eccaca1efface1effacee1facade1face1faceaface1fada1fade1fadee1fad01abbe1acceda1accede1accede1baba1baffe1baffee1ba0bab1bebe1b0b01caca1cacaba1cacabe1caca01cade1cafe1ceda1cede1cedee1c0bea1c0", le = 500
            // var content = "abbe1acceda1accede1accede1baba1baffe1baffee1ba0b", le = 50
            var finalClean = function(){
                console.debug("Go back to MF")
                dongle.selectFile(Daplug.MASTER_FILE)(function(){
                    console.debug("Remove folder 2012")
                    dongle.deleteFileOrDir(0x2012)(function(){
                        console.debug("Test complete !")
                    })
                })
            }
            var fileTest = function(){
                console.debug("Create (and select) file 2014")
                dongle.createFile(0x2014, le)(function(){
                    console.debug("Write > " + content)
                    dongle.write(0, new ByteString(content, HEX))(function(){
                        console.debug("Read file")
                        dongle.read(0, content.length/2)(function(ans){
                            console.debug("Read  > " + ans.toString(HEX))
                            console.debug("Got up (2012)")
                            dongle.selectFile(0x2012)(function(){
                                console.debug("Clean file 2014")
                                dongle.deleteFileOrDir(0x2014)(finalClean)
                            })
                        })
                    })
                })
            }
            var folderTest = function(){
                console.debug("Create (and select) dir 2012")
                dongle.createDir(0x2012, Daplug.ACCESS_ALWAYS)(function(){
                    console.debug("Create (and select) dir 2013")
                    dongle.createDir(0x2013, Daplug.ACCESS_ALWAYS)(function(){
                        console.debug("Go back to 2012")
                        dongle.selectFile(0x2012)(function(){
                            console.debug("Remove folder 2013")
                            dongle.deleteFileOrDir(0x2013)(fileTest)
                        })
                    })
                }, function(err){
                    if (err == 0x6a89) {
                        // file already exists
                        console.debug("File 2012 already exists, deleting it and restarting")
                        dongle.deleteFileOrDir(0x2012)(folderTest)
                    } else console.debug("Ivalid SW: " + toHex(err, 4))
                })
            }
            commonAuth(folderTest)
        }

        var testPutKey = function(){
            var secu = Daplug.C_MAC
            var newKey = new Daplug.KeySet(
                0x87,
                "000102030405060708090A0B0C0D0E0F",
                "101112131415161718191A1B1C1D1E1F",
                "202122232425262728292A2B2C2D2E2F")
            newKey.setKeyAccess(0x0001)
            newKey.setKeyUsage(Daplug.KS.GP)

            var cleanThings = function(){
                console.debug("Authenticating in default keyset to clean things")
                commonAuth(function(){
                    console.debug("Removing keyset: " + toHex(newKey.version))
                    dongle.deleteKey(newKey.version)(function(){
                        console.debug("Keyset deleted !")
                    })
                })
            }
            var doPutKey = function(){
                console.debug("Creating a new GP key")
                dongle.putKey(newKey)(function(){
                    console.debug("Authenticating with new GP key")
                    dongle.authenticate(newKey, secu)(cleanThings)
                })
            }
            commonAuth(doPutKey)
        }

        var testCrypto = function() {

            var cryptoKey = new Daplug.KeySet(0x7b, "404142434445467848494A4B4C4D4E4F")
            cryptoKey.setKeyAccess(0x0001)
            cryptoKey.setKeyUsage(Daplug.KS.ENC_DEC)
            var cv = cryptoKey.version

            var clean = function() {
                console.debug("Removing cryto key ...")
                dongle.deleteKey(cv)(function(){
                    console.debug("Crypto keyset deleted !")
                })
            }

            var message = new ByteString("yoloyolo", ASCII)

            var mode2 = Daplug.CRYPT.ECB
            var decypher2 = function(res){
                console.debug("Decyphering: "+res.toString(HEX))
                dongle.decrypt(cv, 1, mode, res)(function(res){
                    console.debug("GOT: " + res.toString(HEX) + " - " + res.toString(ASCII))
                    clean()
                })
            }
            var cypher2 = function(){
                console.debug("Cyphering a test message in ECB")
                dongle.encrypt(cv, 1, mode, message)(decypher2)
            }

            var mode = Daplug.CRYPT.CBC
            var decypher = function(res){
                console.debug("Decyphering: "+res.toString(HEX))
                dongle.decrypt(cv, 1, mode, res)(function(res){
                    console.debug("GOT: " + res.toString(HEX) + " - " + res.toString(ASCII))
                    cypher2()
                })
            }
            var cypher = function(){
                console.debug("Cyphering a test message in CBC with no IV")
                dongle.encrypt(cv, 1, mode, message)(decypher)
            }

            var doPutKey = function(){
                console.debug("Creating a ENC/DEC key")
                dongle.putKey(cryptoKey)(cypher)
            }
            commonAuth(doPutKey)
        }

        var testHmac = function() {
            var hmacKey = new Daplug.KeySet(0x7b, "404142434445467848494A4B4C4D4E4F")
            hmacKey.setKeyAccess(0x0001)
            hmacKey.setKeyUsage(Daplug.KS.HMAC_SHA1)
            var cv = hmacKey.version
            var data = new ByteString("DECADE20", HEX)

            var clean = function() {
                console.debug("Removing HMAC key ...")
                dongle.deleteKey(cv)(function(){
                    console.debug("HMAC keyset deleted !")
                })
            }

            var runHmac = function(){
                console.debug("Computing HMAC of: " + data.toString(HEX))
                dongle.hmac(cv, 0x00, data)(function(res){
                    console.debug("GOT: " + res.toString(HEX))
                    console.debug("EXP: bf9d0175281bac658e7abd7ea26847ce34dfdc03")
                    if (res.toString(HEX) == "bf9d0175281bac658e7abd7ea26847ce34dfdc03") {
                        console.debug("Got expected value !")
                    }
                    clean()
                })
            }

            var putHmacKey = function(){
                console.debug("Setting a key for HMAC test")
                dongle.putKey(hmacKey)(runHmac)
            }

            commonAuth(putHmacKey)
        }

        var testHotp = function(){
            var hotpKeyVersion = 0x03
            var hotpKey = new ByteString(
                "716704022D872983665A03E6C39EC117C084228A", HEX
            )
            var cf = 0x0042

            var clean = function(){
                console.debug("Removing HOTP key")
                dongle.deleteKey(hotpKeyVersion)(function(){
                    dongle.selectPath([Daplug.MASTER_FILE, 0xC010])(function(){
                        dongle.deleteFileOrDir(cf)(function(){
                            console.debug("Cleaning done")
                        })
                    })
                })
            }

            var testHotp = function(){
                console.debug("Getting HOTP")
                dongle.hmac(
                    hotpKeyVersion,
                    Daplug.OTP.DIGIT_6 + Daplug.OTP.DATA_FILE,
                    new ByteString("0042", HEX)
                )(function(res){
                    console.debug("HOTP 1: " + res.toString(ASCII) + " (Expecting 367191)")
                    dongle.hmac(
                        hotpKeyVersion,
                        Daplug.OTP.DIGIT_6 + Daplug.OTP.DATA_FILE,
                        new ByteString("0042", HEX)
                    )(function(res){
                        console.debug("HOTP 2: " + res.toString(ASCII) + " (Expecting 624290)")
                        clean()
                    }, clean)
                }, clean)
            }

            var configureHotp = function(){
                console.debug("Adding HOTP key")
                dongle.setHotpKey(hotpKeyVersion, hotpKey)(function(){
                    console.debug("Creating a counter file")
                    dongle.selectFile(Daplug.MASTER_FILE)(function(){
                        dongle.createCounterFile(cf, 16)(function(){
                            console.debug("Going home")
                            dongle.selectFile(Daplug.MASTER_FILE)(testHotp)
                        }, clean)
                    })
                })
            }

            commonAuth(configureHotp)
        }

        var testTotp = function(){
            var timeKeyVer = 0x04
            var timeKey = new ByteString("505152535455565758595A5B5C5D5E5F", HEX)

            var totpKeyVer = 0x05
            var b32totpKey = "oftq iarn q4uy gzs2 aptm hhwb c7ai iiuk"
            var totpKey = Daplug.decodeBase32(b32totpKey)

            var clean = function() {
                console.debug("Removing TOTP keys ...")
                dongle.deleteKeys([timeKeyVer, totpKeyVer])(function(){
                    console.debug("HMAC keyset deleted !")
                })
            }

            var getTOTP = function(){
                console.debug("Getting TOTP")
                dongle.totp(totpKeyVer, Daplug.OTP.DIGIT_6)(
                    function(res){
                        console.debug("TOTP: " + res)
                        clean()
                    }
                )
            }

            var setTime = function(){
                console.debug("Setting time ...")
                dongle.setTimeOTP(timeKeyVer, 0x01, timeKey)(getTOTP)
            }

            var setupTotp = function(){
                console.debug("Setting time key")
                dongle.setTotpTimeKey(timeKeyVer, timeKey)(function(){
                    console.debug("Setting TOTP key")
                    dongle.setTotpKey(totpKeyVer, timeKeyVer, totpKey)(setTime)
                })
            }
            commonAuth(setupTotp)
        }

        var testKeyboard = function(){
            var kbFile = 0x0800
            var size = 100
            var message = "coucou"

            var activate = function(){
                console.debug("Associating keyboard file to boot")
                dongle.useAsKeyboard(function(){
                    console.debug("Activating keyboard at boot")
                    dongle.setKeyboardAtBoot(true)(function(){
                        console.debug("KB activated at boot")
                        $("#target").focus()
                    })
                })
            }

            var fillKb = function(){
                console.debug("Filling keyboard file content")
                var kb = new Daplug.KeyBoard()
                kb.addSleep()
                kb.addSleep()
                kb.addSleep()
                kb.addTextWindows(message)
                kb.addSleep()
                kb.addReturn()
                kb.zeroPad(size)
                console.debug("Writing keyboard file")
                console.debug(kb.content.toString(HEX))
                console.debug(kb.getContent().toString(HEX))
                dongle.write(0, kb.getContent())(activate)
            }

            var createKB = function(){
                console.debug("Creating keyboard file")
                dongle.createFile(kbFile, size)(function(){
                    console.debug("Selecting keyboard file")
                    dongle.selectFile(kbFile)(fillKb)
                })
            }
            commonAuth(createKB)
        }

        var cleanKb = function(){
            commonAuth(function(){
                dongle.setKeyboardAtBoot(false)(function(){
                    dongle.deleteFileOrDir(0x0800)(function(){
                        console.debug("Cleaning done")
                    })
                })
            })
        }

        var testSam = function(){
            console.debug("Starting SAM test")
            var samSN = "5046c07189e271b412695337595000010109"
            // Test using Community keyset
            var samCtxKeyVer = 0xFC
            var samCtxKeyID = 1
            var samGPKeyVer = 0x66
            var cardKeyVer = 0x42
            var secu = Daplug.C_MAC + Daplug.C_DEC + Daplug.R_MAC + Daplug.R_ENC
            function testComm(card) {
                return function(){
                    console.debug("SAM AUTH OK")
                    setTimeout(function(){
                        card.getSerial(
                            function(ans){
                                console.debug("Serial: " + ans.toString(HEX))
                                card.getSerial(
                                    function(ans){
                                        console.debug("Serial: " + ans.toString(HEX))
                                    }
                                )
                            }
                        )
                    }, 10)
                }
            }
            function onErr() {
                console.debug("SAM AUTH KO")
            }
            function authSam(samCard, card){
                var sam = new DaplugSAM(samCard)
                card.getChipDiversifier(function(divCard){
                    console.debug("Authenticate with secu 0x"+toHex(secu))
                    card.authenticateSam(sam, samCtxKeyVer, samCtxKeyID, samGPKeyVer, cardKeyVer, secu, divCard)(testComm(card), onErr)
                })
            }
            function findSam(devices){
                Daplug.getDongle(devices[0])(function(card1){
                    card1.getSerial(function(sn1){
                        Daplug.getDongle(devices[1])(function(card2){
                            card2.getSerial(function(sn2){
                                console.debug("SN1: " + sn1.toString(HEX))
                                console.debug("SN2: " + sn2.toString(HEX))
                                if (sn1.toString(HEX) == samSN) authSam(card1, card2)
                                else if (sn2.toString(HEX) == samSN) authSam(card2, card1)
                                else alert("No card with SAM ID found !")
                            })
                        })
                    })
                })
            }
            Daplug.getDongleList(
                function(lst){
                    console.debug(lst.length + " device(s) found")
                    if (lst.length != 2)
                        alert("This test requires exactly two devices: a SAM and a target device")
                    else findSam(lst)
                }
            )
        }

        return {
            cleanKb      : cleanKb,
            selectFirst  : selectFirst,
            testApdu     : testApdu,
            testAuth     : testAuth,
            testCrypto   : testCrypto,
            testFile     : testFile,
            testKeyboard : testKeyboard,
            testHmac     : testHmac,
            testHotp     : testHotp,
            testPutKey   : testPutKey,
            testTotp     : testTotp,
            testSam      : testSam
        }

    }();

    window.PU = PU;
})(window, document);



$(document).ready(function(){
    Daplug.initDaplug()
});
