/**
 * Snippet for Client Side RSA Key Pair.
 */

function signUp(password, callback){
    
    // Returning Values
    var signUpData = {
        pub_key: '',
        priv_key: '',
        iv: '',
        salt: '',
        pseudonym: '',
        password_hash: '',
        aes_key: ''
    }
        
    // Create RSA Key Pair
    createRSA(function(key_pair){
        
        // Assign Public Key to results
        exportKey(key_pair.publicKey, function(public_key){
            signUpData.pub_key = JSON.stringify(public_key);
            
            // Handle Private Key, IV and Pseudonym
            exportKey(key_pair.privateKey, function(private_key){
                
                var priv_key = str2ab(JSON.stringify(private_key));
                
                // Get AES Key derived from password
                getPasswordDerivationKey(password, 1000, null, function(aes_key, salt){
                    
                    signUpData.aes_key = aes_key;
                    signUpData.salt = salt;
                    
                    // Compute ciphered Private Key
                    encryptAES(aes_key, priv_key, "AES-CBC", function(cipher_priv, gen_iv){
                        
                        signUpData.priv_key = ab2str(cipher_priv.buffer);
                        signUpData.iv = ab2str(gen_iv.buffer);
                        
                        // Compute Pseudonym from Private Key
                        computeSHA(priv_key, "SHA-256", function(hash){
                            signUpData.pseudonym = ab2str(hash);
                            
                            // Compute Password Hash
                            computeSHA(str2ab(password), "SHA-256", function(hash){
                                signUpData.password_hash = ab2str(hash);
                                
                                // Send the results back
                                callback(signUpData); 
                            });
                        }); 
                    });
                });           
            });
        });        
    }); 
}

function logInRequest(password, salt, callback){
    
    // Returning Values
    var logInRequestData = {
        aes_key: '',
        password_hash: ''
    }
    // Compute Password Hash
    computeSHA(str2ab(password), "SHA-256", function(hash){
        logInRequestData.password_hash = ab2str(hash);
        
        // Get AES Key derived from password
        getPasswordDerivationKey(password, 1000, salt, function(aes_key, salt){
            
            logInRequestData.aes_key = aes_key;
            // Send the results back
            callback(logInRequestData);
        });
    });
}

function logInResponse(public_key, private_key, iv, pseudonym, aes_key, callback){
    
    // Returing Values
    var logInResponseData = {
        pub_key: '',
        priv_key: '',
        pseudonym: ''
    }
    
    // Get Public Key
    importRSA(JSON.parse(public_key), function(public_key){
        
        logInResponseData.pub_key = public_key;
        var gen_iv = new Uint8Array(str2ab(iv));
        var priv_key = new Uint8Array(str2ab(private_key));

        // Compute Private Key
        decryptAES(aes_key, priv_key, "AES-CBC", gen_iv, function(dec_key){
            
            logInResponseData.priv_key = JSON.parse(ab2str(dec_key));
            
            // Compute Pseudonym from Private Key
            computeSHA(priv_key, "SHA-256", function(hash){
                logInResponseData.pseudonym = ab2str(hash);
                
                callback(logInResponseData);
            });
        });
        
    });
}

function getPasswordDerivationKey(password, iterations, salt, callback){
    
    // Compute Key from password (PBKDF2)
    createKey(str2ab(password), function(sym_key){
        
        // Compute Key derivation (PBKDF2)
        deriveKey(sym_key, iterations, salt, function(der_key, salt){
            
            // Get Key
            exportKey(der_key, function(key){
                
                // Get AES Key
                importAESKey(key, "AES-CBC", function(aes_key){
                    
                    // Send AES Key back
                    callback(aes_key, salt);
                })
            });
        });
    });
}

function createRSA(callback){
    window.crypto.subtle.generateKey(
        {
            name: "RSASSA-PKCS1-v1_5",
            modulusLength: 2048, // 2048 bits
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: {name: "SHA-256"}, 
        },
        true,
        ["sign", "verify"]
    )
    .then(function(key){
        callback(key);
    })
    .catch(function(err){
        console.error(err);
    });
}

function importRSA(key, callback){
    window.crypto.subtle.importKey(
        "jwk",
        key,
        {   
            name: "RSASSA-PKCS1-v1_5",
            hash: {name: "SHA-256"}, 
        },
        false,
        ["verify"] 
    )
    .then(function(publicKey){
        callback(publicKey);
    })
    .catch(function(err){
        console.error(err);
    });
}

function exportKey(key, callback){
    window.crypto.subtle.exportKey(
        "jwk", 
        key 
    )
    .then(function(keydata){
        callback(keydata);
    })
    .catch(function(err){
        console.error(err);
    });
}

function createKey(password, callback){
     window.crypto.subtle.importKey(
        "raw", 
        password, 
        {
            name: "PBKDF2",
        },
        false, 
        ["deriveKey", "deriveBits"] 
    )
    .then(function(key){
        callback(key);
    })
    .catch(function(err){
        console.error(err);
    });
}

function deriveKey(key, iterations, salt, callback){
    
    if(salt == null){
        salt = window.crypto.getRandomValues(new Uint8Array(16));   
    }
    window.crypto.subtle.deriveKey(
        {
            "name": "PBKDF2",
            salt: salt,
            iterations: iterations,
            hash: {name: "SHA-1"}, 
        },
        key,
        { 
            name: "AES-CBC",
            length: 256, 
        },
        true, 
        ["encrypt", "decrypt"]
    )
    .then(function(key){
        callback(key, salt);
    })
    .catch(function(err){
        console.error(err);
    });
}

function importAESKey(key, algorithm, callback){
    window.crypto.subtle.importKey(
        "jwk",
        key,
        {   
            name: algorithm,
        },
        false,
        ["encrypt", "decrypt"]
    )
    .then(function(key){
        callback(key);
    })
    .catch(function(err){
        console.error(err);
    });
}

function encryptAES(key, data, algorithm, callback){
    var iv = window.crypto.getRandomValues(new Uint8Array(16))
    window.crypto.subtle.encrypt(
        {
            name: algorithm,
            iv: iv,
        },
        key,
        data
    )
    .then(function(encrypted){
        callback(new Uint8Array(encrypted), iv);
    })
    .catch(function(err){
        console.error(err);
    });
}

function decryptAES(key, data, algorithm, iv, callback){
    window.crypto.subtle.decrypt(
        {
            name: algorithm,
            iv: iv,
        },
        key,
        data
    )
    .then(function(decrypted){
        callback(new Uint8Array(decrypted).buffer);
    })
    .catch(function(err){
        console.log(err.name);
        console.error(err);
        
    });
}

function computeSHA(data, mode, callback){
    window.crypto.subtle.digest(
        {
            name: mode,
        },
        data
    )
    .then(function(hash){
        callback(new Uint8Array(hash).buffer);
    })
    .catch(function(err){
        console.error(err);
    });
}


// Utils Functions
function str2ab(text) {
  
  var buf = new ArrayBuffer(text.length*2);
  var bufView = new Uint16Array(buf);
  for (var i=0, strLen=text.length; i<strLen; i++) {
    bufView[i] = text.charCodeAt(i);
  }
  return buf;
}

function ab2str(buf){
    
  return String.fromCharCode.apply(null, new Uint16Array(buf));
}
