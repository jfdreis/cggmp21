use std::iter;

use cggmp21_tests::external_verifier::ExternalVerifier;
use generic_ec::{coords::HasAffineX, Curve, Point};
use rand::seq::SliceRandom;
use rand::{Rng, RngCore};
use rand_dev::DevRng;
use sha2::Sha256;

use cggmp21::key_share::AnyKeyShare;
use cggmp21::signing::DataToSign;
use cggmp21::{security_level::SecurityLevel128, ExecutionId};

#[test]
fn signing_from_issue() {
    let key_shares = serde_json::json!([
        {
            "chain_code": "a182236512e8d94cc1ec4f8ca0239cdc7c2b3d2a125b443aad67a1e5355a890c",
            "curve": "secp256k1",
            "i": 0,
            "public_shares": [
                "0335e902402f8c7df3852353abe4ee61e372076556532714f3fd7242d8172503dd",
                "0213a864a4fa94ae9488e5078a1b870485fc5db4b7def8ca18fa43ec7bace6d77a",
                "02c35093d1841ea350513e5fa3b60ac554a49a8f5554c5b0e0b47578f85768d11b"
            ],
            "shared_public_key": "0321def5bb4a05a5d36a247f62e8fff00321b0186bee89295bd4002681329dfafa",
            "vss_setup": {
                "I": [
                    "0000000000000000000000000000000000000000000000000000000000000001",
                    "0000000000000000000000000000000000000000000000000000000000000002",
                    "0000000000000000000000000000000000000000000000000000000000000003"
                ],
                "min_signers": 2
            },
            "x": "cacd6bc4e655824da76672fdf6868136df17eb92a5a418d9cbadce1eae358bd7"
        },
        {
            "chain_code": "a182236512e8d94cc1ec4f8ca0239cdc7c2b3d2a125b443aad67a1e5355a890c",
            "curve": "secp256k1",
            "i": 1,
            "public_shares": [
                "0335e902402f8c7df3852353abe4ee61e372076556532714f3fd7242d8172503dd",
                "0213a864a4fa94ae9488e5078a1b870485fc5db4b7def8ca18fa43ec7bace6d77a",
                "02c35093d1841ea350513e5fa3b60ac554a49a8f5554c5b0e0b47578f85768d11b"
            ],
            "shared_public_key": "0321def5bb4a05a5d36a247f62e8fff00321b0186bee89295bd4002681329dfafa",
            "vss_setup": {
                "I": [
                    "0000000000000000000000000000000000000000000000000000000000000001",
                    "0000000000000000000000000000000000000000000000000000000000000002",
                    "0000000000000000000000000000000000000000000000000000000000000003"
                ],
                "min_signers": 2
            },
            "x": "0ec371804b683f15ce06abfb218f353439e8c86ffd10263e00e9b3665a33e6d5"
        },
        {
            "chain_code": "a182236512e8d94cc1ec4f8ca0239cdc7c2b3d2a125b443aad67a1e5355a890c",
            "curve": "secp256k1",
            "i": 2,
            "public_shares": [
                "0335e902402f8c7df3852353abe4ee61e372076556532714f3fd7242d8172503dd",
                "0213a864a4fa94ae9488e5078a1b870485fc5db4b7def8ca18fa43ec7bace6d77a",
                "02c35093d1841ea350513e5fa3b60ac554a49a8f5554c5b0e0b47578f85768d11b"
            ],
            "shared_public_key": "0321def5bb4a05a5d36a247f62e8fff00321b0186bee89295bd4002681329dfafa",
            "vss_setup": {
                "I": [
                    "0000000000000000000000000000000000000000000000000000000000000001",
                    "0000000000000000000000000000000000000000000000000000000000000002",
                    "0000000000000000000000000000000000000000000000000000000000000003"
                ],
                "min_signers": 2
            },
            "x": "52b9773bb07afbddf4a6e4f84c97e9304f68823403c4d3ddf5f7f73ad6688314"
        }
    ]);

    let aux_data = serde_json::json!([
        {
            "p": {
                "radix": 16,
                "value": "c0fc872da6e53bbb399a69eb33ac9f132ccfd308713b1c60cdc6b5b92a9a5c96b00c16fdf36b10cfa85ff21d533481c192b5c8a96e4e599d50b23f0436864ede875085a2224b494db97245c0705b903d53d950b2fac06db47c374411e6627dca7d18cbfd4854a7607e7451eadffbce2663448ac29d7de50b3b8fb3665f35f11e5a24590b56e56dd87a55b6bc10366b73a65e9555af668c6c55685dd7f114c2763f6a24d928b9413a13b642a22c51212c13d8d4dd20750deb59d018a4c61e882f"
            },
            "parties": [
                {
                    "N": {
                        "radix": 16,
                        "value": "769ab461a832492d1454a7c0e2249102196035647f4637e083e94eb6f5dfc2ad1ed8e75f3a0fcc9330b4e26276d1ffe63c636fe9b9f7272e11fcd9c96fb39db093288ba90c11cae85b96ad18cfc7b14c7d85030ea60b8030e6224617ef636f4c1dfc1634fcfbe56d7b0971deae4e1643dd228f56817af1147bc4c36ddf694c16f8be0f898222737fc74e1703c168e38dfa3a612ae7d6bfa373f090bfdacb72909806d3989e4956aeafc552c7a07d5f550347272abf7caf7fa6151445771d992439012e0f56bdb244fccbae135aa1f8da67e21ab1abecddc3024a5d3af84fe5e0ba69b19e3ab2eb5373d62b8acbe18846a5f2dcd3a95cfe24fcad51bc799aca76ea8ce5fbb1b12458833e6330620a000d20423080283134fe0feb278589eb4fa0b0bbf84508fa65eb0a3897a117440f6b94886f333cd423af7d4fecca1d466446a4572684001ec310fe6bcb873d5db2e62c3d8e01ae1070c927a52b7749a39f5e9fd983b1735a7f43f634624d9072d515e53a33a3a95f72dce1a070a9cdbb1951"
                    },
                    "crt": null,
                    "multiexp": null,
                    "s": {
                        "radix": 16,
                        "value": "5ffe971e5c772b7de33f967f64957a781065bd8c13d68e4d819a158689ee1fff3b7d8de92c50b2ed1841f888a7089751a605bd26fac507c9018706913bd29f0a0d906522f83774630f942773fdf929e009150b62e8fc2c24f33688e1bfbe3d65aa42008e19d0f5a6dcbf40b95812c6fd4b023b402aa00b9692b4abdb4b7308866d1e69e554252e4030deb2227391efe5cb10bd2234c2d2cf9017b49e5544a960e21b2d6e74c7891a8f4590938cefe8d7395e53f8c53874937f9cbfc53ca4f09c11537082c6533525f735c94cfd66f115e8e19c06ecec1b87a7903a5a6edcb9a8f9db36894eaae0b819cb83084ea1c6ffee0c1ad2f8476451cfefef0fb15deed633c2e5bd8e5da5107a9f1324832c4207a9557a5349e8fd95b357b39e24fb66883a1afc7380040d851f9a26ca1909ea1b3ca5cb27e6df27ac1d9d16907a08b6cd80979c3258a210e87ad3c8df4c09def173a15575dadcb65ffde934136df12ccf686880a5b42568e0f16b84ba5b6937b54ff0f0fc4c216016789e67135c8378ba"
                    },
                    "t": {
                        "radix": 16,
                        "value": "261cf67e1f37af782edfb51b62ec9b2d06973ed657c193309bf289bbeee279c3c14431ff61578fbf91022d2c0cd72e6855df7f2d85bab7c4c9f78ba22ddd5388a831e5b68e291d67d87615c6dce67917a212666687b2156b1d9143b7b0ebe35abd4d2ab9cb33e8de2c15caa0ba1167b75c2306b4d1f6cbfd1053442197fbbad2bb3362a7277d4c199d68a3588053c26c5f30dda275d7a6044a41b3dfd1ddaa27048d2e55ecd153e7f0e9b94766bf431d3e66a2bddb4ac7465d11fbf81509fa431de4e87238edc9fbfab7ca35e4da140a66854cce0f2a2c4cb0e089bc610eae657af7eb478992fd3643e22e26c678102d0e5b1ddafe61e37656d4624fc88cd3c7893c1af0de3270ecb57b785c9113cbc8977dbe77e83a07da70a00c19ac4307ca9ef347abe13d94b07704dbcf6145763f462d12217216bc39e4499b0ec717f307c278b0fbf6d4aca8de69155f8a332739abd73ef7ba12e7fad834d9265856aa1ac57777decfe703a77af3bc3254abc6ace3241c4e9c8d3375b9fb758df191f915"
                    }
                },
                {
                    "N": {
                        "radix": 16,
                        "value": "e9cecdffe5e028dec432c09cdf2039b2154d5dbfe7385ac8a3c9b1004e42138ae8186de694eb3d8bd00bbad3b992dd52e1e27dee1a0b07c114373d28b79b9cbb7ba0de1bd314858368bf3eb670b25bf450817ba2d8941c4b2e84a43e24d0a246a0d2b292cb9278609ba31dbc784f8a2d0c16532363f9beabeee0c002f587b8533a97b8ef475a068c7acf09e4fb3d7eb02d58fe66f33ea2276f2fe6fab7e3ce06b80c75064bfdf953ba2f0c33c8922de802fcda47157dc62988e035fb87666a78be0981599fa840271986f9110616bd9606cc49b46be132458556e6c2a83d08cc1d696389b7657683b7b7550643c13c0236d04c34dce2da09ab7205daae8d62e2a750825ac0c7c47b339ae0ed81c8edd2dad9778a2920fc05722777f1556b04e32374d758b102f88df6d6f39209cbe84b814b6028d63fc22da7418067ad6629c80887be5950627b3876755d736db495171357d9a46aa629165cb1d1ac37c9b4adaf2a381c53c44af4f3ea9164af203f05d08dd6b0bb12df4f43bcd2b36fa74729"
                    },
                    "crt": null,
                    "multiexp": null,
                    "s": {
                        "radix": 16,
                        "value": "490e066c437e7553a9cd29588b0cc4725df899934e2003d7d841c79ad81c43ae1d03fedb51be1637dcf98397687b233187e863eba19dd23e84c7088e3ef72bef0e83b490af4a6b64faa1d1f90b034e1a1875b1514fbf1011a2d8cd2422bac677be4a83abb3d06b0345b6ee53424f6c57d7428bf7d360730ec8d31ae3da0c66a740d5aa7990abef78343bfa97080d1d025c75681bed3e6e7bc4027ef6da29903c3ad74b506237756f6ca4d5b6196d166f52abd3f6ee81db702841616ed5d382c54578fc5f293f3d6d9d933c897ef02eb11854fb26239ffe8f0d342228beb4a24b8d3aeb30a64eacbf5960a461eb2e698d6d1b63d751ac14e33c90b533abb99f003b51ce14b9a827c6279c1afa3a35ad5bf261591691921b65f304eb71de5a80214ad3e36eb183ff6ad08785573d73dbfb1faa00b0f96cd6f49eb7263a351e979dd7b9b844e6f6008b816b5c3fe01923e219c7fc0d3c79c190b51b38b3a54d56868759ce98aa4adbf7e7f5c9827ecf927b8eb77d6e0c9c2e87a41a0f13d621a9f0"
                    },
                    "t": {
                        "radix": 16,
                        "value": "781c6bf87946c280262b8618f29cf15766555b77d5d0f4cc673deef420a99d73c92abebd327d3fdd7f8b3552b8a8ee08777fa52619c7dada101a3b9415b0e72b326e261231af79575155adadefa544ee4642b1569bc7ced0035a2a288e715da4fe3dcbe144925d58129768e6e6fd4738944b52c4f9a24af12c7f60d44528195be72972aa4fdb1885507591d5aeaccaed770cb4aa7a71ec96509227cec4c1714c3a2f428f87bf977899dfbc8178ec0fb950d7c234e978f653cfc6b42f367983cc48b04f7ca9c215e0caaaa6a57ac6c0b0c86b14294858fb35562e53bb966b5a87e4ca6f136e0b419c76e9a4671d22f816c95561c05d770848ddd808bd56d838dcbd3c542ef0ff874899029fb65dcce5548c1d7230cdce63ce515c89a8048fde8852949aa375d10128522bb50e3e60ad70d944c9e864e6af70629adc2f34989cae25b0fac1e0d169bf58e4d4a605f1c7aa7600495c5128decd0b87df486f2edd509b0b8694ad02a08745a7574a568686e4ff9f78fe72cf9606f75bfaa6f97d0c77"
                    }
                },
                {
                    "N": {
                        "radix": 16,
                        "value": "98d5cba2c6c447541ab4143df0737df6923c665c933039c02079657bd29fbf156509ea7b28e78ea6a4e33bbbc149e429e8d4ba3becbbeada27bb043f10035ffed7897cd7c2a76dd9188ff965e2066a1773ff8f58469f7294510840ee1b4b6ece66a7c2e9b4ce69b89542c0580f3a1bcf82e61db421ca46ecdba0dad8e6aab721c883e376d78933b64ed42a2ec2315ce5d7f133f5f60630b7588c5359839a9e0f02c61290be549705abce591331456842a0b8dbcd6a5eeee3a9aad685cb332330bec255e00527f4666435ce3675461e844a42ec9744c63e97c9924b8ddf374b825b21b7960f2d84a30c92b7c2c1996d9c06f7dfd52bf6561bdec93479cd1518ca93577744b9d597f9a55edce8d29abebb5d8e613a29b07c4c92e4b22be4b9b66ec37a2809caa9df747945cfdf144f7cf64cddfb0580709be72e47ee1856277d169d71733c55cdded4c19ea12db48eaf7c31683a9041d77d68e6111e86c77b5d898ca05181314bdfa2d592d4254820689d8e0057129aa743f96b1e001b82c2d9d5"
                    },
                    "crt": null,
                    "multiexp": null,
                    "s": {
                        "radix": 16,
                        "value": "178dd24cd1d4be4c2c9c0da4e5c083209382ab6223824c65b4638c1c4f418361a00683109a9f94af7495a3133bdab3b59d6af88164fa1798dcfa9cbbeab8ae26a6a636eeca83f1161f92d486edd6e4d9035707631208cc27f15cf0f4c1eaa9fb538760c435b584a47e3e45173ce877e84a93a36928acac8d2e430a32c64201d98af755fa22447d5c6ff45a6bf2d4b1676521224249a113e96a46bc1fd4343253bfaa1b62e96c76b8efbef43b06bbf668ce077936bcf2bf71e46074a6a5ff3e4968c5ee0f6a363b15c72dcc802ec6983ea6962e5fc8fded7cd18cb09b8d766808f20ff0abf8a1af72a779cd06f0394ce406e052f02eaebad176610b07c1e253b50f150005f109b0596f03f3e0f3e4649cfb760b3402a41eddb46d46fb79181a453558281216e65edce9131c0798e321a9540efc7b1c8083aa1610e0c50d1bad380e9824e5f26c759a93dff79403151c6ad3b31fbedbb61507e8d9915dc5d55bd776c31331090cf6efa77785ab6d5e255d0376ad9cb3feee96bdcd90db7d3d1759"
                    },
                    "t": {
                        "radix": 16,
                        "value": "b003a5790ee87bda60a2015792da0e796b4ce3ccaf46fbc9cf447b7ede28f5c5d1669721839ad4ccd8d966e2da151fee2fe0d734f2830004704a363f77e4d0b57b34b5dfa31bcdd07d6995c75fd583dc8896cb45f7960897e4e52a23e562a89ecff682624b88dd901eb45a76561986e746aa07d2744069acb3dfd0caf9eee9a3c521b66b6343a470563f52a07645e43e17320fba24c88b4d11a403abe9304ab3070f822b7d5dc8ef0cc1e1d86b42477f2a0e55118fbc12cb20a049d3177ef5ff994353f0ffced3d115cfb1541922f020d748032a3c01655084cac8ea89b54fb3af606072ffdc300de349ff9a274f333c3b0ce658f40caa95fd2efd677676928411af3fd02916ad392bed6962f45700816281fb58b30c551d38604d9395e310a2e7b89cbfadd21110d6a24a8686338625df7a6db437eb5ccf77aeb591ce3d7c47bb795b2c6721d0d5fc62622aef6768a7be57e4410c3e2ab1e6fb2b01d78d73cb69856c1cfdf1e2a006f6a28bae3cbad53888760df5745e7b9897c35866d9ac6"
                    }
                }
            ],
            "q": {
                "radix": 16,
                "value": "9d54ad4483e6c226c84446531affb6c2e82ae82ee954e68c45e22a61e1ecbe57e782daae54ae410382e0e75fd5b3341f6260cede9d7f772ffb76af4cdaf8ecf33694726cd9dd50acbfc1d7255fa04ebbd2b351479f930594bf8a238b562e799996924eddcfd3d0f78fa04155f3bc3350aee18b0d1be0f977bf6e755c4d3a451424d36321bb6a8c73b27aab1aa646b55bd8a3380f3619184eb4d64b9a0b41e0bc4ec5e430ca01025e7c1f24b96d1623bebffd1f3400563e5c2028cf90ef56967f"
            }
        },
        {
            "p": {
                "radix": 16,
                "value": "eba85df41331bbdabb45ae5f13009579ce80001ca98696c841a18a53352af1c24fb8058c0e105d294865fa03e0b17614a1ccf6e07cc804122bb588dcc0ba560304446df8d8ae4d91b19656d322ce6f66c4bba825dcbc3efe6fc14d6934597387b472843052adbb031daa4fcaee7582f194be137592c24e1229c509d2a3e25d9a0a7f32d47ead46f573ce7e8df77fde5a022d68ad86f41c1860fe4372a24a4980b7b1bad64d4fd29b02dd700ca9ac9c724c1e7002983f8069f0140e8bd231f357"
            },
            "parties": [
                {
                    "N": {
                        "radix": 16,
                        "value": "769ab461a832492d1454a7c0e2249102196035647f4637e083e94eb6f5dfc2ad1ed8e75f3a0fcc9330b4e26276d1ffe63c636fe9b9f7272e11fcd9c96fb39db093288ba90c11cae85b96ad18cfc7b14c7d85030ea60b8030e6224617ef636f4c1dfc1634fcfbe56d7b0971deae4e1643dd228f56817af1147bc4c36ddf694c16f8be0f898222737fc74e1703c168e38dfa3a612ae7d6bfa373f090bfdacb72909806d3989e4956aeafc552c7a07d5f550347272abf7caf7fa6151445771d992439012e0f56bdb244fccbae135aa1f8da67e21ab1abecddc3024a5d3af84fe5e0ba69b19e3ab2eb5373d62b8acbe18846a5f2dcd3a95cfe24fcad51bc799aca76ea8ce5fbb1b12458833e6330620a000d20423080283134fe0feb278589eb4fa0b0bbf84508fa65eb0a3897a117440f6b94886f333cd423af7d4fecca1d466446a4572684001ec310fe6bcb873d5db2e62c3d8e01ae1070c927a52b7749a39f5e9fd983b1735a7f43f634624d9072d515e53a33a3a95f72dce1a070a9cdbb1951"
                    },
                    "crt": null,
                    "multiexp": null,
                    "s": {
                        "radix": 16,
                        "value": "5ffe971e5c772b7de33f967f64957a781065bd8c13d68e4d819a158689ee1fff3b7d8de92c50b2ed1841f888a7089751a605bd26fac507c9018706913bd29f0a0d906522f83774630f942773fdf929e009150b62e8fc2c24f33688e1bfbe3d65aa42008e19d0f5a6dcbf40b95812c6fd4b023b402aa00b9692b4abdb4b7308866d1e69e554252e4030deb2227391efe5cb10bd2234c2d2cf9017b49e5544a960e21b2d6e74c7891a8f4590938cefe8d7395e53f8c53874937f9cbfc53ca4f09c11537082c6533525f735c94cfd66f115e8e19c06ecec1b87a7903a5a6edcb9a8f9db36894eaae0b819cb83084ea1c6ffee0c1ad2f8476451cfefef0fb15deed633c2e5bd8e5da5107a9f1324832c4207a9557a5349e8fd95b357b39e24fb66883a1afc7380040d851f9a26ca1909ea1b3ca5cb27e6df27ac1d9d16907a08b6cd80979c3258a210e87ad3c8df4c09def173a15575dadcb65ffde934136df12ccf686880a5b42568e0f16b84ba5b6937b54ff0f0fc4c216016789e67135c8378ba"
                    },
                    "t": {
                        "radix": 16,
                        "value": "261cf67e1f37af782edfb51b62ec9b2d06973ed657c193309bf289bbeee279c3c14431ff61578fbf91022d2c0cd72e6855df7f2d85bab7c4c9f78ba22ddd5388a831e5b68e291d67d87615c6dce67917a212666687b2156b1d9143b7b0ebe35abd4d2ab9cb33e8de2c15caa0ba1167b75c2306b4d1f6cbfd1053442197fbbad2bb3362a7277d4c199d68a3588053c26c5f30dda275d7a6044a41b3dfd1ddaa27048d2e55ecd153e7f0e9b94766bf431d3e66a2bddb4ac7465d11fbf81509fa431de4e87238edc9fbfab7ca35e4da140a66854cce0f2a2c4cb0e089bc610eae657af7eb478992fd3643e22e26c678102d0e5b1ddafe61e37656d4624fc88cd3c7893c1af0de3270ecb57b785c9113cbc8977dbe77e83a07da70a00c19ac4307ca9ef347abe13d94b07704dbcf6145763f462d12217216bc39e4499b0ec717f307c278b0fbf6d4aca8de69155f8a332739abd73ef7ba12e7fad834d9265856aa1ac57777decfe703a77af3bc3254abc6ace3241c4e9c8d3375b9fb758df191f915"
                    }
                },
                {
                    "N": {
                        "radix": 16,
                        "value": "e9cecdffe5e028dec432c09cdf2039b2154d5dbfe7385ac8a3c9b1004e42138ae8186de694eb3d8bd00bbad3b992dd52e1e27dee1a0b07c114373d28b79b9cbb7ba0de1bd314858368bf3eb670b25bf450817ba2d8941c4b2e84a43e24d0a246a0d2b292cb9278609ba31dbc784f8a2d0c16532363f9beabeee0c002f587b8533a97b8ef475a068c7acf09e4fb3d7eb02d58fe66f33ea2276f2fe6fab7e3ce06b80c75064bfdf953ba2f0c33c8922de802fcda47157dc62988e035fb87666a78be0981599fa840271986f9110616bd9606cc49b46be132458556e6c2a83d08cc1d696389b7657683b7b7550643c13c0236d04c34dce2da09ab7205daae8d62e2a750825ac0c7c47b339ae0ed81c8edd2dad9778a2920fc05722777f1556b04e32374d758b102f88df6d6f39209cbe84b814b6028d63fc22da7418067ad6629c80887be5950627b3876755d736db495171357d9a46aa629165cb1d1ac37c9b4adaf2a381c53c44af4f3ea9164af203f05d08dd6b0bb12df4f43bcd2b36fa74729"
                    },
                    "crt": null,
                    "multiexp": null,
                    "s": {
                        "radix": 16,
                        "value": "490e066c437e7553a9cd29588b0cc4725df899934e2003d7d841c79ad81c43ae1d03fedb51be1637dcf98397687b233187e863eba19dd23e84c7088e3ef72bef0e83b490af4a6b64faa1d1f90b034e1a1875b1514fbf1011a2d8cd2422bac677be4a83abb3d06b0345b6ee53424f6c57d7428bf7d360730ec8d31ae3da0c66a740d5aa7990abef78343bfa97080d1d025c75681bed3e6e7bc4027ef6da29903c3ad74b506237756f6ca4d5b6196d166f52abd3f6ee81db702841616ed5d382c54578fc5f293f3d6d9d933c897ef02eb11854fb26239ffe8f0d342228beb4a24b8d3aeb30a64eacbf5960a461eb2e698d6d1b63d751ac14e33c90b533abb99f003b51ce14b9a827c6279c1afa3a35ad5bf261591691921b65f304eb71de5a80214ad3e36eb183ff6ad08785573d73dbfb1faa00b0f96cd6f49eb7263a351e979dd7b9b844e6f6008b816b5c3fe01923e219c7fc0d3c79c190b51b38b3a54d56868759ce98aa4adbf7e7f5c9827ecf927b8eb77d6e0c9c2e87a41a0f13d621a9f0"
                    },
                    "t": {
                        "radix": 16,
                        "value": "781c6bf87946c280262b8618f29cf15766555b77d5d0f4cc673deef420a99d73c92abebd327d3fdd7f8b3552b8a8ee08777fa52619c7dada101a3b9415b0e72b326e261231af79575155adadefa544ee4642b1569bc7ced0035a2a288e715da4fe3dcbe144925d58129768e6e6fd4738944b52c4f9a24af12c7f60d44528195be72972aa4fdb1885507591d5aeaccaed770cb4aa7a71ec96509227cec4c1714c3a2f428f87bf977899dfbc8178ec0fb950d7c234e978f653cfc6b42f367983cc48b04f7ca9c215e0caaaa6a57ac6c0b0c86b14294858fb35562e53bb966b5a87e4ca6f136e0b419c76e9a4671d22f816c95561c05d770848ddd808bd56d838dcbd3c542ef0ff874899029fb65dcce5548c1d7230cdce63ce515c89a8048fde8852949aa375d10128522bb50e3e60ad70d944c9e864e6af70629adc2f34989cae25b0fac1e0d169bf58e4d4a605f1c7aa7600495c5128decd0b87df486f2edd509b0b8694ad02a08745a7574a568686e4ff9f78fe72cf9606f75bfaa6f97d0c77"
                    }
                },
                {
                    "N": {
                        "radix": 16,
                        "value": "98d5cba2c6c447541ab4143df0737df6923c665c933039c02079657bd29fbf156509ea7b28e78ea6a4e33bbbc149e429e8d4ba3becbbeada27bb043f10035ffed7897cd7c2a76dd9188ff965e2066a1773ff8f58469f7294510840ee1b4b6ece66a7c2e9b4ce69b89542c0580f3a1bcf82e61db421ca46ecdba0dad8e6aab721c883e376d78933b64ed42a2ec2315ce5d7f133f5f60630b7588c5359839a9e0f02c61290be549705abce591331456842a0b8dbcd6a5eeee3a9aad685cb332330bec255e00527f4666435ce3675461e844a42ec9744c63e97c9924b8ddf374b825b21b7960f2d84a30c92b7c2c1996d9c06f7dfd52bf6561bdec93479cd1518ca93577744b9d597f9a55edce8d29abebb5d8e613a29b07c4c92e4b22be4b9b66ec37a2809caa9df747945cfdf144f7cf64cddfb0580709be72e47ee1856277d169d71733c55cdded4c19ea12db48eaf7c31683a9041d77d68e6111e86c77b5d898ca05181314bdfa2d592d4254820689d8e0057129aa743f96b1e001b82c2d9d5"
                    },
                    "crt": null,
                    "multiexp": null,
                    "s": {
                        "radix": 16,
                        "value": "178dd24cd1d4be4c2c9c0da4e5c083209382ab6223824c65b4638c1c4f418361a00683109a9f94af7495a3133bdab3b59d6af88164fa1798dcfa9cbbeab8ae26a6a636eeca83f1161f92d486edd6e4d9035707631208cc27f15cf0f4c1eaa9fb538760c435b584a47e3e45173ce877e84a93a36928acac8d2e430a32c64201d98af755fa22447d5c6ff45a6bf2d4b1676521224249a113e96a46bc1fd4343253bfaa1b62e96c76b8efbef43b06bbf668ce077936bcf2bf71e46074a6a5ff3e4968c5ee0f6a363b15c72dcc802ec6983ea6962e5fc8fded7cd18cb09b8d766808f20ff0abf8a1af72a779cd06f0394ce406e052f02eaebad176610b07c1e253b50f150005f109b0596f03f3e0f3e4649cfb760b3402a41eddb46d46fb79181a453558281216e65edce9131c0798e321a9540efc7b1c8083aa1610e0c50d1bad380e9824e5f26c759a93dff79403151c6ad3b31fbedbb61507e8d9915dc5d55bd776c31331090cf6efa77785ab6d5e255d0376ad9cb3feee96bdcd90db7d3d1759"
                    },
                    "t": {
                        "radix": 16,
                        "value": "b003a5790ee87bda60a2015792da0e796b4ce3ccaf46fbc9cf447b7ede28f5c5d1669721839ad4ccd8d966e2da151fee2fe0d734f2830004704a363f77e4d0b57b34b5dfa31bcdd07d6995c75fd583dc8896cb45f7960897e4e52a23e562a89ecff682624b88dd901eb45a76561986e746aa07d2744069acb3dfd0caf9eee9a3c521b66b6343a470563f52a07645e43e17320fba24c88b4d11a403abe9304ab3070f822b7d5dc8ef0cc1e1d86b42477f2a0e55118fbc12cb20a049d3177ef5ff994353f0ffced3d115cfb1541922f020d748032a3c01655084cac8ea89b54fb3af606072ffdc300de349ff9a274f333c3b0ce658f40caa95fd2efd677676928411af3fd02916ad392bed6962f45700816281fb58b30c551d38604d9395e310a2e7b89cbfadd21110d6a24a8686338625df7a6db437eb5ccf77aeb591ce3d7c47bb795b2c6721d0d5fc62622aef6768a7be57e4410c3e2ab1e6fb2b01d78d73cb69856c1cfdf1e2a006f6a28bae3cbad53888760df5745e7b9897c35866d9ac6"
                    }
                }
            ],
            "q": {
                "radix": 16,
                "value": "fdfd8f205a57bc91fbbfd8aa2c82d64ee3699cf10e037acb13fa5f4e302c8da219418e7f4d16f3414a5f594c1d7c1e407ee0e9053b21688f74748cc4aad7d2b2c4db7aa2e3679595d4ea0568b703fa7e5ebdc7104d94bded198a456256f268703ea1b60c324e5c17567d4ba15d8620abd9d6930baeeb053590a6d1bc72730d694cc5e2a4d06fe66bf075670e19b36ef886ce4bedac7a41b9a769fd9ce2e5c622ad14cf8f3710c4dd33ce26302cd84abc9da162712f648f1a1fb4fd0c0dca897f"
            }
        },
        {
            "p": {
                "radix": 16,
                "value": "b5e13af95b1cbec523ae444b5ad44ca08ad51854ffe5b833c1a0a1579cc2c9278d18535e3dc19070c4c30dbb88ce6feb11890f7219192581544428c3c8409df49403a913276c11c06f92705e4a21f583b06834bbd9dc358edc21e409c8f542f90c84154226f562a39bc772ae5afe82566612161af28ad0881040e60c961fc24b6beb325b6b7648b9e244d54db2c983b6ed58b333714f50f0690133847160b44f49d45f3b52bc6eee16f9b5122464c30d35ff78534a4c7d01bce755d7c78defc3"
            },
            "parties": [
                {
                    "N": {
                        "radix": 16,
                        "value": "769ab461a832492d1454a7c0e2249102196035647f4637e083e94eb6f5dfc2ad1ed8e75f3a0fcc9330b4e26276d1ffe63c636fe9b9f7272e11fcd9c96fb39db093288ba90c11cae85b96ad18cfc7b14c7d85030ea60b8030e6224617ef636f4c1dfc1634fcfbe56d7b0971deae4e1643dd228f56817af1147bc4c36ddf694c16f8be0f898222737fc74e1703c168e38dfa3a612ae7d6bfa373f090bfdacb72909806d3989e4956aeafc552c7a07d5f550347272abf7caf7fa6151445771d992439012e0f56bdb244fccbae135aa1f8da67e21ab1abecddc3024a5d3af84fe5e0ba69b19e3ab2eb5373d62b8acbe18846a5f2dcd3a95cfe24fcad51bc799aca76ea8ce5fbb1b12458833e6330620a000d20423080283134fe0feb278589eb4fa0b0bbf84508fa65eb0a3897a117440f6b94886f333cd423af7d4fecca1d466446a4572684001ec310fe6bcb873d5db2e62c3d8e01ae1070c927a52b7749a39f5e9fd983b1735a7f43f634624d9072d515e53a33a3a95f72dce1a070a9cdbb1951"
                    },
                    "crt": null,
                    "multiexp": null,
                    "s": {
                        "radix": 16,
                        "value": "5ffe971e5c772b7de33f967f64957a781065bd8c13d68e4d819a158689ee1fff3b7d8de92c50b2ed1841f888a7089751a605bd26fac507c9018706913bd29f0a0d906522f83774630f942773fdf929e009150b62e8fc2c24f33688e1bfbe3d65aa42008e19d0f5a6dcbf40b95812c6fd4b023b402aa00b9692b4abdb4b7308866d1e69e554252e4030deb2227391efe5cb10bd2234c2d2cf9017b49e5544a960e21b2d6e74c7891a8f4590938cefe8d7395e53f8c53874937f9cbfc53ca4f09c11537082c6533525f735c94cfd66f115e8e19c06ecec1b87a7903a5a6edcb9a8f9db36894eaae0b819cb83084ea1c6ffee0c1ad2f8476451cfefef0fb15deed633c2e5bd8e5da5107a9f1324832c4207a9557a5349e8fd95b357b39e24fb66883a1afc7380040d851f9a26ca1909ea1b3ca5cb27e6df27ac1d9d16907a08b6cd80979c3258a210e87ad3c8df4c09def173a15575dadcb65ffde934136df12ccf686880a5b42568e0f16b84ba5b6937b54ff0f0fc4c216016789e67135c8378ba"
                    },
                    "t": {
                        "radix": 16,
                        "value": "261cf67e1f37af782edfb51b62ec9b2d06973ed657c193309bf289bbeee279c3c14431ff61578fbf91022d2c0cd72e6855df7f2d85bab7c4c9f78ba22ddd5388a831e5b68e291d67d87615c6dce67917a212666687b2156b1d9143b7b0ebe35abd4d2ab9cb33e8de2c15caa0ba1167b75c2306b4d1f6cbfd1053442197fbbad2bb3362a7277d4c199d68a3588053c26c5f30dda275d7a6044a41b3dfd1ddaa27048d2e55ecd153e7f0e9b94766bf431d3e66a2bddb4ac7465d11fbf81509fa431de4e87238edc9fbfab7ca35e4da140a66854cce0f2a2c4cb0e089bc610eae657af7eb478992fd3643e22e26c678102d0e5b1ddafe61e37656d4624fc88cd3c7893c1af0de3270ecb57b785c9113cbc8977dbe77e83a07da70a00c19ac4307ca9ef347abe13d94b07704dbcf6145763f462d12217216bc39e4499b0ec717f307c278b0fbf6d4aca8de69155f8a332739abd73ef7ba12e7fad834d9265856aa1ac57777decfe703a77af3bc3254abc6ace3241c4e9c8d3375b9fb758df191f915"
                    }
                },
                {
                    "N": {
                        "radix": 16,
                        "value": "e9cecdffe5e028dec432c09cdf2039b2154d5dbfe7385ac8a3c9b1004e42138ae8186de694eb3d8bd00bbad3b992dd52e1e27dee1a0b07c114373d28b79b9cbb7ba0de1bd314858368bf3eb670b25bf450817ba2d8941c4b2e84a43e24d0a246a0d2b292cb9278609ba31dbc784f8a2d0c16532363f9beabeee0c002f587b8533a97b8ef475a068c7acf09e4fb3d7eb02d58fe66f33ea2276f2fe6fab7e3ce06b80c75064bfdf953ba2f0c33c8922de802fcda47157dc62988e035fb87666a78be0981599fa840271986f9110616bd9606cc49b46be132458556e6c2a83d08cc1d696389b7657683b7b7550643c13c0236d04c34dce2da09ab7205daae8d62e2a750825ac0c7c47b339ae0ed81c8edd2dad9778a2920fc05722777f1556b04e32374d758b102f88df6d6f39209cbe84b814b6028d63fc22da7418067ad6629c80887be5950627b3876755d736db495171357d9a46aa629165cb1d1ac37c9b4adaf2a381c53c44af4f3ea9164af203f05d08dd6b0bb12df4f43bcd2b36fa74729"
                    },
                    "crt": null,
                    "multiexp": null,
                    "s": {
                        "radix": 16,
                        "value": "490e066c437e7553a9cd29588b0cc4725df899934e2003d7d841c79ad81c43ae1d03fedb51be1637dcf98397687b233187e863eba19dd23e84c7088e3ef72bef0e83b490af4a6b64faa1d1f90b034e1a1875b1514fbf1011a2d8cd2422bac677be4a83abb3d06b0345b6ee53424f6c57d7428bf7d360730ec8d31ae3da0c66a740d5aa7990abef78343bfa97080d1d025c75681bed3e6e7bc4027ef6da29903c3ad74b506237756f6ca4d5b6196d166f52abd3f6ee81db702841616ed5d382c54578fc5f293f3d6d9d933c897ef02eb11854fb26239ffe8f0d342228beb4a24b8d3aeb30a64eacbf5960a461eb2e698d6d1b63d751ac14e33c90b533abb99f003b51ce14b9a827c6279c1afa3a35ad5bf261591691921b65f304eb71de5a80214ad3e36eb183ff6ad08785573d73dbfb1faa00b0f96cd6f49eb7263a351e979dd7b9b844e6f6008b816b5c3fe01923e219c7fc0d3c79c190b51b38b3a54d56868759ce98aa4adbf7e7f5c9827ecf927b8eb77d6e0c9c2e87a41a0f13d621a9f0"
                    },
                    "t": {
                        "radix": 16,
                        "value": "781c6bf87946c280262b8618f29cf15766555b77d5d0f4cc673deef420a99d73c92abebd327d3fdd7f8b3552b8a8ee08777fa52619c7dada101a3b9415b0e72b326e261231af79575155adadefa544ee4642b1569bc7ced0035a2a288e715da4fe3dcbe144925d58129768e6e6fd4738944b52c4f9a24af12c7f60d44528195be72972aa4fdb1885507591d5aeaccaed770cb4aa7a71ec96509227cec4c1714c3a2f428f87bf977899dfbc8178ec0fb950d7c234e978f653cfc6b42f367983cc48b04f7ca9c215e0caaaa6a57ac6c0b0c86b14294858fb35562e53bb966b5a87e4ca6f136e0b419c76e9a4671d22f816c95561c05d770848ddd808bd56d838dcbd3c542ef0ff874899029fb65dcce5548c1d7230cdce63ce515c89a8048fde8852949aa375d10128522bb50e3e60ad70d944c9e864e6af70629adc2f34989cae25b0fac1e0d169bf58e4d4a605f1c7aa7600495c5128decd0b87df486f2edd509b0b8694ad02a08745a7574a568686e4ff9f78fe72cf9606f75bfaa6f97d0c77"
                    }
                },
                {
                    "N": {
                        "radix": 16,
                        "value": "98d5cba2c6c447541ab4143df0737df6923c665c933039c02079657bd29fbf156509ea7b28e78ea6a4e33bbbc149e429e8d4ba3becbbeada27bb043f10035ffed7897cd7c2a76dd9188ff965e2066a1773ff8f58469f7294510840ee1b4b6ece66a7c2e9b4ce69b89542c0580f3a1bcf82e61db421ca46ecdba0dad8e6aab721c883e376d78933b64ed42a2ec2315ce5d7f133f5f60630b7588c5359839a9e0f02c61290be549705abce591331456842a0b8dbcd6a5eeee3a9aad685cb332330bec255e00527f4666435ce3675461e844a42ec9744c63e97c9924b8ddf374b825b21b7960f2d84a30c92b7c2c1996d9c06f7dfd52bf6561bdec93479cd1518ca93577744b9d597f9a55edce8d29abebb5d8e613a29b07c4c92e4b22be4b9b66ec37a2809caa9df747945cfdf144f7cf64cddfb0580709be72e47ee1856277d169d71733c55cdded4c19ea12db48eaf7c31683a9041d77d68e6111e86c77b5d898ca05181314bdfa2d592d4254820689d8e0057129aa743f96b1e001b82c2d9d5"
                    },
                    "crt": null,
                    "multiexp": null,
                    "s": {
                        "radix": 16,
                        "value": "178dd24cd1d4be4c2c9c0da4e5c083209382ab6223824c65b4638c1c4f418361a00683109a9f94af7495a3133bdab3b59d6af88164fa1798dcfa9cbbeab8ae26a6a636eeca83f1161f92d486edd6e4d9035707631208cc27f15cf0f4c1eaa9fb538760c435b584a47e3e45173ce877e84a93a36928acac8d2e430a32c64201d98af755fa22447d5c6ff45a6bf2d4b1676521224249a113e96a46bc1fd4343253bfaa1b62e96c76b8efbef43b06bbf668ce077936bcf2bf71e46074a6a5ff3e4968c5ee0f6a363b15c72dcc802ec6983ea6962e5fc8fded7cd18cb09b8d766808f20ff0abf8a1af72a779cd06f0394ce406e052f02eaebad176610b07c1e253b50f150005f109b0596f03f3e0f3e4649cfb760b3402a41eddb46d46fb79181a453558281216e65edce9131c0798e321a9540efc7b1c8083aa1610e0c50d1bad380e9824e5f26c759a93dff79403151c6ad3b31fbedbb61507e8d9915dc5d55bd776c31331090cf6efa77785ab6d5e255d0376ad9cb3feee96bdcd90db7d3d1759"
                    },
                    "t": {
                        "radix": 16,
                        "value": "b003a5790ee87bda60a2015792da0e796b4ce3ccaf46fbc9cf447b7ede28f5c5d1669721839ad4ccd8d966e2da151fee2fe0d734f2830004704a363f77e4d0b57b34b5dfa31bcdd07d6995c75fd583dc8896cb45f7960897e4e52a23e562a89ecff682624b88dd901eb45a76561986e746aa07d2744069acb3dfd0caf9eee9a3c521b66b6343a470563f52a07645e43e17320fba24c88b4d11a403abe9304ab3070f822b7d5dc8ef0cc1e1d86b42477f2a0e55118fbc12cb20a049d3177ef5ff994353f0ffced3d115cfb1541922f020d748032a3c01655084cac8ea89b54fb3af606072ffdc300de349ff9a274f333c3b0ce658f40caa95fd2efd677676928411af3fd02916ad392bed6962f45700816281fb58b30c551d38604d9395e310a2e7b89cbfadd21110d6a24a8686338625df7a6db437eb5ccf77aeb591ce3d7c47bb795b2c6721d0d5fc62622aef6768a7be57e4410c3e2ab1e6fb2b01d78d73cb69856c1cfdf1e2a006f6a28bae3cbad53888760df5745e7b9897c35866d9ac6"
                    }
                }
            ],
            "q": {
                "radix": 16,
                "value": "d71e746b84897f16cf1abf5d4a3664de2d9fb82640d05b11deca1fdb25537964e04360abc6bbe2569800929328d215b2b0041e0514ed6eb3437445a405f08e461597d7bdc03e0697453958bb9539147f620b0f6a240e4121d2c2eeefbb9a9b0fc4bd6b32f3baebc016cac861150bfd2a5181c0870331187272c94d1cf03b447e01c19f4cb5b0cbb1070675b8f0d99d88ec10423529b8b80d037c029a23af4761b0275938058753a6010e79bfe124b3adea1586686a000fa4dd5eff9056f44e87"
            }
        }
    ]);

    use generic_ec::curves::secp256k1::E;
    let key_shares: Vec<cggmp21::IncompleteKeyShare<E>> =
        serde_json::from_value(key_shares).unwrap();
    let aux_data: Vec<cggmp21::key_share::AuxInfo> = serde_json::from_value(aux_data).unwrap();

    let key_shares = key_shares
        .into_iter()
        .zip(aux_data)
        .map(|(share, aux)| cggmp21::KeyShare::from_parts((share, aux)))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    // only two key shares are needed to sign
    let key_shares = &key_shares[0..2];

    let message_to_sign = cggmp21::DataToSign::digest::<sha2::Sha256>(b"hello");

    let mut rng = rand_dev::DevRng::new();
    let eid: [u8; 32] = rng.gen();
    let eid = cggmp21::ExecutionId::new(&eid);
    round_based::sim::run_with_setup(key_shares, |i, party, share| {
        let mut rng = rng.fork();
        let signing = cggmp21::signing(eid, i, &[0, 1], share);
        async move { signing.sign(&mut rng, party, message_to_sign).await }
    })
    .unwrap()
    .expect_ok()
    .expect_eq();
}

cggmp21_tests::test_suite! {
    test: signing_works,
    generics: all_curves,
    suites: {
        n2: (None, 2, false, false),
        n2_reliable: (None, 2, true, false),
        t2n2: (Some(2), 2, false, false),
        n3: (None, 3, false, false),
        t2n3: (Some(2), 3, false, false),
        t3n3: (Some(3), 3, false, false),

        #[cfg(feature = "hd-wallet")]
        n3_hd: (None, 3, false, true),
        #[cfg(feature = "hd-wallet")]
        t2n3_hd: (Some(2), 3, false, true),
        #[cfg(feature = "hd-wallet")]
        t3n3_hd: (Some(3), 3, false, true),
    }
}

fn signing_works<E>(t: Option<u16>, n: u16, reliable_broadcast: bool, hd_wallet: bool)
where
    E: Curve + cggmp21_tests::CurveParams,
    Point<E>: HasAffineX<E>,
{
    #[cfg(not(feature = "hd-wallet"))]
    assert!(!hd_wallet);

    let mut rng = DevRng::new();

    let shares = cggmp21_tests::CACHED_SHARES
        .get_shares::<E, SecurityLevel128>(t, n, hd_wallet)
        .expect("retrieve cached shares");

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let mut original_message_to_sign = [0u8; 100];
    rng.fill_bytes(&mut original_message_to_sign);
    let message_to_sign = DataToSign::digest::<Sha256>(&original_message_to_sign);

    #[cfg(feature = "hd-wallet")]
    let derivation_path = if hd_wallet {
        Some(cggmp21_tests::random_derivation_path(&mut rng))
    } else {
        None
    };

    // Choose `t` signers to perform signing
    let t = shares[0].min_signers();
    let mut participants = (0..n).collect::<Vec<_>>();
    participants.shuffle(&mut rng);
    let participants = &participants[..usize::from(t)];
    println!("Signers: {participants:?}");
    let participants_shares = participants.iter().map(|i| &shares[usize::from(*i)]);

    let sig = round_based::sim::run_with_setup(participants_shares, |i, party, share| {
        let party = cggmp21_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();

        let signing = cggmp21::signing(eid, i, participants, share)
            .enforce_reliable_broadcast(reliable_broadcast);

        #[cfg(feature = "hd-wallet")]
        let signing = if let Some(derivation_path) = derivation_path.clone() {
            signing
                .set_derivation_path_with_algo::<E::HdAlgo, _>(derivation_path)
                .unwrap()
        } else {
            signing
        };

        async move { signing.sign(&mut party_rng, party, message_to_sign).await }
    })
    .unwrap()
    .expect_ok()
    .expect_eq();

    #[cfg(feature = "hd-wallet")]
    let public_key = if let Some(path) = &derivation_path {
        generic_ec::NonZero::from_point(
            shares[0]
                .derive_child_public_key::<E::HdAlgo, _>(path.iter().cloned())
                .unwrap()
                .public_key,
        )
        .unwrap()
    } else {
        shares[0].shared_public_key
    };
    #[cfg(not(feature = "hd-wallet"))]
    let public_key = shares[0].shared_public_key;

    sig.verify(&public_key, &message_to_sign)
        .expect("signature is not valid");

    E::ExVerifier::verify(&public_key, &sig, &original_message_to_sign)
        .expect("external verification failed")
}

cggmp21_tests::test_suite! {
    test: signing_with_presigs,
    generics: all_curves,
    suites: {
        t3n5: (Some(3), 5, false),
        #[cfg(feature = "hd-wallet")]
        t3n5_hd: (Some(3), 5, false),
    }
}

fn signing_with_presigs<E>(t: Option<u16>, n: u16, hd_wallet: bool)
where
    E: Curve + cggmp21_tests::CurveParams,
    Point<E>: HasAffineX<E>,
{
    #[cfg(not(feature = "hd-wallet"))]
    assert!(!hd_wallet);

    let mut rng = DevRng::new();

    let shares = cggmp21_tests::CACHED_SHARES
        .get_shares::<E, SecurityLevel128>(t, n, hd_wallet)
        .expect("retrieve cached shares");

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    // Choose `t` signers to generate presignature
    let t = shares[0].min_signers();
    let mut participants = (0..n).collect::<Vec<_>>();
    participants.shuffle(&mut rng);
    let participants = &participants[..usize::from(t)];
    println!("Signers: {participants:?}");

    let participants_shares = participants.iter().map(|i| &shares[usize::from(*i)]);

    let presigs = round_based::sim::run_with_setup(participants_shares, |i, party, share| {
        let party = cggmp21_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();

        async move {
            cggmp21::signing(eid, i, participants, share)
                .generate_presignature(&mut party_rng, party)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .into_vec();

    // Now, that we have presignatures generated, we learn (generate) a messages to sign
    // and the derivation path (if hd is enabled)
    let mut original_message_to_sign = [0u8; 100];
    rng.fill_bytes(&mut original_message_to_sign);
    let message_to_sign = DataToSign::digest::<Sha256>(&original_message_to_sign);

    #[cfg(feature = "hd-wallet")]
    let derivation_path = if hd_wallet {
        Some(cggmp21_tests::random_derivation_path(&mut rng))
    } else {
        None
    };

    let partial_signatures = presigs
        .into_iter()
        .map(|presig| {
            #[cfg(feature = "hd-wallet")]
            let presig = if let Some(derivation_path) = &derivation_path {
                let epub = shares[0].extended_public_key().expect("not hd wallet");
                presig
                    .set_derivation_path_with_algo::<E::HdAlgo, _>(
                        epub,
                        derivation_path.iter().copied(),
                    )
                    .unwrap()
            } else {
                presig
            };
            presig.issue_partial_signature(message_to_sign)
        })
        .collect::<Vec<_>>();

    let signature = cggmp21::PartialSignature::combine(&partial_signatures)
        .expect("invalid partial sigantures");

    #[cfg(feature = "hd-wallet")]
    let public_key = if let Some(path) = &derivation_path {
        generic_ec::NonZero::from_point(
            shares[0]
                .derive_child_public_key::<E::HdAlgo, _>(path.iter().cloned())
                .unwrap()
                .public_key,
        )
        .unwrap()
    } else {
        shares[0].shared_public_key
    };
    #[cfg(not(feature = "hd-wallet"))]
    let public_key = shares[0].shared_public_key;

    signature
        .verify(&public_key, &message_to_sign)
        .expect("signature is not valid");

    E::ExVerifier::verify(&public_key, &signature, &original_message_to_sign)
        .expect("external verification failed")
}

cggmp21_tests::test_suite! {
    test: signing_sync,
    generics: all_curves,
    suites: {
        n3: (None, 3, false),
        t3n5: (Some(3), 5, false),
        #[cfg(feature = "hd-wallet")]
        n3_hd: (None, 3, true),
        #[cfg(feature = "hd-wallet")]
        t3n5_hd: (Some(3), 5, true),
    }
}

fn signing_sync<E>(t: Option<u16>, n: u16, hd_wallet: bool)
where
    E: Curve + cggmp21_tests::CurveParams,
    Point<E>: HasAffineX<E>,
{
    #[cfg(not(feature = "hd-wallet"))]
    assert!(!hd_wallet);

    let mut rng = DevRng::new();

    let shares = cggmp21_tests::CACHED_SHARES
        .get_shares::<E, SecurityLevel128>(t, n, hd_wallet)
        .expect("retrieve cached shares");

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let mut original_message_to_sign = [0u8; 100];
    rng.fill_bytes(&mut original_message_to_sign);
    let message_to_sign = DataToSign::digest::<Sha256>(&original_message_to_sign);

    #[cfg(feature = "hd-wallet")]
    let derivation_path = if hd_wallet {
        Some(cggmp21_tests::random_derivation_path(&mut rng))
    } else {
        None
    };

    // Choose `t` signers to perform signing
    let t = shares[0].min_signers();
    let mut participants = (0..n).collect::<Vec<_>>();
    participants.shuffle(&mut rng);
    let participants = &participants[..usize::from(t)];
    println!("Signers: {participants:?}");
    let participants_shares = participants.iter().map(|i| &shares[usize::from(*i)]);

    let mut signer_rng = iter::repeat_with(|| rng.fork())
        .take(n.into())
        .collect::<Vec<_>>();

    let mut simulation = round_based::sim::Simulation::with_capacity(n);

    for ((i, share), signer_rng) in (0..).zip(participants_shares).zip(&mut signer_rng) {
        simulation.add_party({
            let signing = cggmp21::signing(eid, i, participants, share);

            #[cfg(feature = "hd-wallet")]
            let signing = if let Some(derivation_path) = derivation_path.clone() {
                signing
                    .set_derivation_path_with_algo::<E::HdAlgo, _>(derivation_path)
                    .unwrap()
            } else {
                signing
            };

            signing.sign_sync(signer_rng, message_to_sign)
        })
    }

    let sig = simulation.run().unwrap().expect_ok().expect_eq();

    #[cfg(feature = "hd-wallet")]
    let public_key = if let Some(path) = &derivation_path {
        generic_ec::NonZero::from_point(
            shares[0]
                .derive_child_public_key::<E::HdAlgo, _>(path.iter().cloned())
                .unwrap()
                .public_key,
        )
        .unwrap()
    } else {
        shares[0].shared_public_key
    };
    #[cfg(not(feature = "hd-wallet"))]
    let public_key = shares[0].shared_public_key;

    sig.verify(&public_key, &message_to_sign)
        .expect("signature is not valid");

    E::ExVerifier::verify(&public_key, &sig, &original_message_to_sign)
        .expect("external verification failed")
}
