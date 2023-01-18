<?php


use drmonkeyninja\AppleJWT;
use PHPUnit\Framework\TestCase;



    function typeof($var) {
        if (is_object($var)) {
            return get_class($var);
        } else if (is_array($var)) {
            return 'array of '.count($var).' elements';
        } else if (is_string($var)) {
            return 'string of '.strlen($var).' chars';
        } else {
            return gettype($var);
        } 
    }

class JWTTest2 extends TestCase
{

    // public function x_testAppleJWT() {

    //     echo "\n\n";

    //     $appleJWT = new AppleJWT(file_get_contents(__DIR__ . '/data/signedPayload.json'));

    //     echo "-- $appleJWT->signedPayloadDict is ". typeof($appleJWT->signedPayloadDict) ."\n\n";


    //     $signedPayloadDict = file_get_contents(__DIR__ . '/data/signedPayload.json');
    //     echo "signedPayloadDict is ". typeof($signedPayloadDict) ."\n\n";

    //     # echo "signedPayload=". $signedPayload ."\n\n";

    //     $signedPayload = json_decode($signedPayloadDict)->signedPayload;
    //     echo "signedPayload is ". typeof($signedPayload) ."\n\n";
    // }

  

    public function test_JWT_Apple() {

        echo "\n\n";

        $appleJWT = new AppleJWT(file_get_contents(__DIR__ . '/data/signedPayload.json'));

        echo "---- appleJWT->signedPayloadDict is ". typeof($appleJWT->signedPayloadDict) ."\n\n";
        echo "---- appleJWT->signedPayload is ". typeof($appleJWT->signedPayload) ."\n\n";
        echo "---- appleJWT->signedPayloadParts is ". typeof($appleJWT->signedPayloadParts) ."\n\n";

        echo "---- appleJWT->signedPayload_header is ". typeof($appleJWT->signedPayload_header) ."\n\n";
        echo "---- appleJWT->signedPayload_payload is ". typeof($appleJWT->signedPayload_payload) ."\n\n";
        echo "---- appleJWT->signedPayload_signature_provided is ". typeof($appleJWT->signedPayload_signature_provided) ."\n\n";

        echo "---- appleJWT->signedPayload_header_alg is ". typeof($appleJWT->signedPayload_header_alg) ."\n\n";
        echo "---- appleJWT->signedPayload_header_x5c is ". typeof($appleJWT->signedPayload_header_x5c) ."\n\n";

        #echo "---- appleJWT->signedPayload_payload= ". $appleJWT->signedPayload_payload ."\n\n"; // ---- appleJWT->signedPayload_payload= {"notificationType":"EXPIRED","subtype":"VOLUNTARY"

        echo "---- appleJWT->signedPayload_payload_notificationType= ". $appleJWT->signedPayload_payload_notificationType ."\n\n";
        echo "---- appleJWT->signedPayload_payload_subtype= ". $appleJWT->signedPayload_payload_subtype ."\n\n";
        echo "---- appleJWT->signedPayload_payload_notificationUUID= ". $appleJWT->signedPayload_payload_notificationUUID ."\n\n";

        echo "---- appleJWT->signedPayload_payload_data is ". typeof($appleJWT->signedPayload_payload_data) ."\n\n"; // is stdClass

        //   echo "---- appleJWT->signedPayload_payload_data= ". $appleJWT->signedPayload_payload_data ."\n\n";  

        echo "---- appleJWT->signedPayload_payload_data_bundleId= ". $appleJWT->signedPayload_payload_data_bundleId ."\n\n";
        echo "---- appleJWT->signedPayload_payload_data_bundleVersion= ". $appleJWT->signedPayload_payload_data_bundleVersion ."\n\n";

        echo "---- appleJWT->signedPayload_payload_data_environment= ". $appleJWT->signedPayload_payload_data_environment ."\n\n";

        echo "---- appleJWT->signedPayload_payload_data_signedTransactionInfo is ". typeof($appleJWT->signedPayload_payload_data_signedTransactionInfo) ."\n\n";

        // echo "---- appleJWT->signedPayload_payload_data_signedTransactionInfo= ". $appleJWT->signedPayload_payload_data_signedTransactionInfo ."\n\n";

        echo "---- appleJWT->signedPayload_payload_data_signedTransactionInfo_parts is ". typeof($appleJWT->signedPayload_payload_data_signedTransactionInfo_parts) ."\n\n";

        echo "---- signedPayload_payload_data_signedTransactionInfo_part_1 is ". typeof($appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1) ."\n\n";

        echo "---- signedPayload_payload_data_signedTransactionInfo_part_1= ". $appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1 ."\n\n";

      
        // final 14 properties

        echo "---- signedPayload_payload_data_signedTransactionInfo_part_1_transactionId= ". $appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1_transactionId ."\n\n";
        echo "---- signedPayload_payload_data_signedTransactionInfo_part_1_originalTransactionId= ". $appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1_originalTransactionId ."\n\n";
        echo "---- signedPayload_payload_data_signedTransactionInfo_part_1_webOrderLineItemId= ". $appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1_webOrderLineItemId ."\n\n";

        echo "---- signedPayload_payload_data_signedTransactionInfo_part_1_bundleId= ". $appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1_bundleId ."\n\n";
        echo "---- signedPayload_payload_data_signedTransactionInfo_part_1_productId= ". $appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1_productId ."\n\n";
        echo "---- signedPayload_payload_data_signedTransactionInfo_part_1_subscriptionGroupIdentifier= ". $appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1_subscriptionGroupIdentifier ."\n\n";

        echo "---- signedPayload_payload_data_signedTransactionInfo_part_1_purchaseDate= ". $appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1_purchaseDate ."\n\n";
        echo "---- signedPayload_payload_data_signedTransactionInfo_part_1_originalPurchaseDate= ". $appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1_originalPurchaseDate ."\n\n";
        echo "---- signedPayload_payload_data_signedTransactionInfo_part_1_expiresDate= ". $appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1_expiresDate ."\n\n";

        echo "---- signedPayload_payload_data_signedTransactionInfo_part_1_quantity= ". $appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1_quantity ."\n\n";
        echo "---- signedPayload_payload_data_signedTransactionInfo_part_1_type= ". $appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1_type ."\n\n";
        echo "---- signedPayload_payload_data_signedTransactionInfo_part_1_inAppOwnershipType= ". $appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1_inAppOwnershipType ."\n\n";

        echo "---- signedPayload_payload_data_signedTransactionInfo_part_1_signedDate= ". $appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1_signedDate ."\n\n";
        echo "---- signedPayload_payload_data_signedTransactionInfo_part_1_environment= ". $appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1_environment ."\n\n";

        echo "----------------------------------------------------------------------\n\n";

        $this->assertEquals($appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1_transactionId, "2000000251171798");
        $this->assertEquals($appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1_originalTransactionId, "1000000636285238");
        $this->assertEquals($appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1_webOrderLineItemId, "2000000018867885");

        $this->assertEquals($appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1_bundleId, "com.share-telematics.StickPlan1");
        $this->assertEquals($appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1_productId, "SPLPS");
        $this->assertEquals($appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1_subscriptionGroupIdentifier, "20605699");

        $this->assertEquals($appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1_purchaseDate, "1673880327000");
        $this->assertEquals($appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1_originalPurchaseDate, "1583681241000");
        $this->assertEquals($appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1_expiresDate, "1673880627000");

        $this->assertEquals($appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1_quantity, "1");
        $this->assertEquals($appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1_type, "Auto-Renewable Subscription");
        $this->assertEquals($appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1_inAppOwnershipType, "PURCHASED");

        $this->assertEquals($appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1_signedDate, "1673880631072");
        $this->assertEquals($appleJWT->signedPayload_payload_data_signedTransactionInfo_part_1_environment, "Sandbox");

        $this->assertTrue(TRUE == TRUE);

    }
  

    public function x_test_JWT() {

        // data to be encoded in the JWT

        $headers = array('alg'=>'ES256','typ'=>'JWT');
        $payload = array('sub'=>'1234567890','name'=>'John Doe', 'admin'=>true, 'exp'=>1673966474);

        $expected  = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImV4cCI6MTY3Mzk2NjQ3NH0.gcjUjVoU-MR2IYAoYCEvWG7AkMitJZE8u-6CVQjMveM';

        // generate jwt
        $jwt = generate_jwt($headers, $payload);

        echo "\njwt= $jwt\n";

        // check if the jwt is as expected
        $this->assertEquals($expected, $jwt);

        // check if the jwt is valid
        [$is_signature_valid, $is_token_expired] = is_jwt_valid($jwt);

        echo "is_signature_valid: $is_signature_valid, is_token_expired: $is_token_expired\n";


        $this->assertEquals(TRUE, $is_signature_valid);

        $this->assertEquals(TRUE, $is_token_expired);
    }

/*


    public function testMalformedUtf8StringsFail()
    {
        $this->expectException(DomainException::class);
        JWT::encode(['message' => pack('c', 128)], 'a', 'HS256');
    }

    public function testMalformedJsonThrowsException()
    {
        $this->expectException(DomainException::class);
        JWT::jsonDecode('this is not valid JSON string');
    }

    public function testExpiredToken()
    {
        $this->expectException(ExpiredException::class);
        $payload = [
            'message' => 'abc',
            'exp' => time() - 20, // time in the past
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        JWT::decode($encoded, new Key('my_key', 'HS256'));
    }

    public function testBeforeValidTokenWithNbf()
    {
        $this->expectException(BeforeValidException::class);
        $payload = [
            'message' => 'abc',
            'nbf' => time() + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        JWT::decode($encoded, new Key('my_key', 'HS256'));
    }

    public function testBeforeValidTokenWithIat()
    {
        $this->expectException(BeforeValidException::class);
        $payload = [
            'message' => 'abc',
            'iat' => time() + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        JWT::decode($encoded, new Key('my_key', 'HS256'));
    }

    public function testValidToken()
    {
        $payload = [
            'message' => 'abc',
            'exp' => time() + JWT::$leeway + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $decoded = JWT::decode($encoded, new Key('my_key', 'HS256'));
        $this->assertSame($decoded->message, 'abc');
    }

    public function testValidTokenWithLeeway()
    {
        JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'exp' => time() - 20, // time in the past
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $decoded = JWT::decode($encoded, new Key('my_key', 'HS256'));
        $this->assertSame($decoded->message, 'abc');
        JWT::$leeway = 0;
    }

    public function testExpiredTokenWithLeeway()
    {
        JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'exp' => time() - 70, // time far in the past
        ];
        $this->expectException(ExpiredException::class);
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $decoded = JWT::decode($encoded, new Key('my_key', 'HS256'));
        $this->assertSame($decoded->message, 'abc');
        JWT::$leeway = 0;
    }

    public function testValidTokenWithNbf()
    {
        $payload = [
            'message' => 'abc',
            'iat' => time(),
            'exp' => time() + 20, // time in the future
            'nbf' => time() - 20
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $decoded = JWT::decode($encoded, new Key('my_key', 'HS256'));
        $this->assertSame($decoded->message, 'abc');
    }

    public function testValidTokenWithNbfLeeway()
    {
        JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'nbf'     => time() + 20, // not before in near (leeway) future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $decoded = JWT::decode($encoded, new Key('my_key', 'HS256'));
        $this->assertSame($decoded->message, 'abc');
        JWT::$leeway = 0;
    }

    public function testInvalidTokenWithNbfLeeway()
    {
        JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'nbf'     => time() + 65,  // not before too far in future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $this->expectException(BeforeValidException::class);
        JWT::decode($encoded, new Key('my_key', 'HS256'));
        JWT::$leeway = 0;
    }

    public function testValidTokenWithIatLeeway()
    {
        JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'iat'     => time() + 20, // issued in near (leeway) future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $decoded = JWT::decode($encoded, new Key('my_key', 'HS256'));
        $this->assertSame($decoded->message, 'abc');
        JWT::$leeway = 0;
    }

    public function testInvalidTokenWithIatLeeway()
    {
        JWT::$leeway = 60;
        $payload = [
            'message' => 'abc',
            'iat'     => time() + 65, // issued too far in future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $this->expectException(BeforeValidException::class);
        JWT::decode($encoded, new Key('my_key', 'HS256'));
        JWT::$leeway = 0;
    }

    public function testInvalidToken()
    {
        $payload = [
            'message' => 'abc',
            'exp' => time() + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $this->expectException(SignatureInvalidException::class);
        JWT::decode($encoded, new Key('my_key2', 'HS256'));
    }

    public function testNullKeyFails()
    {
        $payload = [
            'message' => 'abc',
            'exp' => time() + JWT::$leeway + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $this->expectException(TypeError::class);
        JWT::decode($encoded, new Key(null, 'HS256'));
    }

    public function testEmptyKeyFails()
    {
        $payload = [
            'message' => 'abc',
            'exp' => time() + JWT::$leeway + 20, // time in the future
        ];
        $encoded = JWT::encode($payload, 'my_key', 'HS256');
        $this->expectException(InvalidArgumentException::class);
        JWT::decode($encoded, new Key('', 'HS256'));
    }

    public function testKIDChooser()
    {
        $keys = [
            '1' => new Key('my_key', 'HS256'),
            '2' => new Key('my_key2', 'HS256')
        ];
        $msg = JWT::encode(['message' => 'abc'], $keys['1']->getKeyMaterial(), 'HS256', '1');
        $decoded = JWT::decode($msg, $keys);
        $expected = new stdClass();
        $expected->message = 'abc';
        $this->assertEquals($decoded, $expected);
    }

    public function testArrayAccessKIDChooser()
    {
        $keys = new ArrayObject([
            '1' => new Key('my_key', 'HS256'),
            '2' => new Key('my_key2', 'HS256'),
        ]);
        $msg = JWT::encode(['message' => 'abc'], $keys['1']->getKeyMaterial(), 'HS256', '1');
        $decoded = JWT::decode($msg, $keys);
        $expected = new stdClass();
        $expected->message = 'abc';
        $this->assertEquals($decoded, $expected);
    }

    public function testNoneAlgorithm()
    {
        $msg = JWT::encode(['message' => 'abc'], 'my_key', 'HS256');
        $this->expectException(UnexpectedValueException::class);
        JWT::decode($msg, new Key('my_key', 'none'));
    }

    public function testIncorrectAlgorithm()
    {
        $msg = JWT::encode(['message' => 'abc'], 'my_key', 'HS256');
        $this->expectException(UnexpectedValueException::class);
        JWT::decode($msg, new Key('my_key', 'RS256'));
    }

    public function testEmptyAlgorithm()
    {
        $msg = JWT::encode(['message' => 'abc'], 'my_key', 'HS256');
        $this->expectException(InvalidArgumentException::class);
        JWT::decode($msg, new Key('my_key', ''));
    }

    public function testAdditionalHeaders()
    {
        $msg = JWT::encode(['message' => 'abc'], 'my_key', 'HS256', null, ['cty' => 'test-eit;v=1']);
        $expected = new stdClass();
        $expected->message = 'abc';
        $this->assertEquals(JWT::decode($msg, new Key('my_key', 'HS256')), $expected);
    }

    public function testInvalidSegmentCount()
    {
        $this->expectException(UnexpectedValueException::class);
        JWT::decode('brokenheader.brokenbody', new Key('my_key', 'HS256'));
    }

    public function testInvalidSignatureEncoding()
    {
        $msg = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwibmFtZSI6ImZvbyJ9.Q4Kee9E8o0Xfo4ADXvYA8t7dN_X_bU9K5w6tXuiSjlUxx';
        $this->expectException(UnexpectedValueException::class);
        JWT::decode($msg, new Key('secret', 'HS256'));
    }

    public function testHSEncodeDecode()
    {
        $msg = JWT::encode(['message' => 'abc'], 'my_key', 'HS256');
        $expected = new stdClass();
        $expected->message = 'abc';
        $this->assertEquals(JWT::decode($msg, new Key('my_key', 'HS256')), $expected);
    }

    public function testRSEncodeDecode()
    {
        $privKey = openssl_pkey_new(['digest_alg' => 'sha256',
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $msg = JWT::encode(['message' => 'abc'], $privKey, 'RS256');
        $pubKey = openssl_pkey_get_details($privKey);
        $pubKey = $pubKey['key'];
        $decoded = JWT::decode($msg, new Key($pubKey, 'RS256'));
        $expected = new stdClass();
        $expected->message = 'abc';
        $this->assertEquals($decoded, $expected);
    }

    public function testEdDsaEncodeDecode()
    {
        $keyPair = sodium_crypto_sign_keypair();
        $privKey = base64_encode(sodium_crypto_sign_secretkey($keyPair));

        $payload = ['foo' => 'bar'];
        $msg = JWT::encode($payload, $privKey, 'EdDSA');

        $pubKey = base64_encode(sodium_crypto_sign_publickey($keyPair));
        $decoded = JWT::decode($msg, new Key($pubKey, 'EdDSA'));
        $this->assertSame('bar', $decoded->foo);
    }

    public function testInvalidEdDsaEncodeDecode()
    {
        $keyPair = sodium_crypto_sign_keypair();
        $privKey = base64_encode(sodium_crypto_sign_secretkey($keyPair));

        $payload = ['foo' => 'bar'];
        $msg = JWT::encode($payload, $privKey, 'EdDSA');

        // Generate a different key.
        $keyPair = sodium_crypto_sign_keypair();
        $pubKey = base64_encode(sodium_crypto_sign_publickey($keyPair));
        $this->expectException(SignatureInvalidException::class);
        JWT::decode($msg, new Key($pubKey, 'EdDSA'));
    }

    public function testRSEncodeDecodeWithPassphrase()
    {
        $privateKey = openssl_pkey_get_private(
            file_get_contents(__DIR__ . '/data/rsa-with-passphrase.pem'),
            'passphrase'
        );

        $jwt = JWT::encode(['message' => 'abc'], $privateKey, 'RS256');
        $keyDetails = openssl_pkey_get_details($privateKey);
        $pubKey = $keyDetails['key'];
        $decoded = JWT::decode($jwt, new Key($pubKey, 'RS256'));
        $expected = new stdClass();
        $expected->message = 'abc';
        $this->assertEquals($decoded, $expected);
    }

    public function testDecodesEmptyArrayAsObject()
    {
        $key = 'yma6Hq4XQegCVND8ef23OYgxSrC3IKqk';
        $payload = [];
        $jwt = JWT::encode($payload, $key, 'HS256');
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));
        $this->assertEquals((object) $payload, $decoded);
    }

    public function testDecodesArraysInJWTAsArray()
    {
        $key = 'yma6Hq4XQegCVND8ef23OYgxSrC3IKqk';
        $payload = ['foo' => [1, 2, 3]];
        $jwt = JWT::encode($payload, $key, 'HS256');
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));
        $this->assertSame($payload['foo'], $decoded->foo);
    }


    // 
    // @runInSeparateProcess
    // @dataProvider provideEncodeDecode
    // 
    public function testEncodeDecode($privateKeyFile, $publicKeyFile, $alg)
    {
        $privateKey = file_get_contents($privateKeyFile);
        $payload = ['foo' => 'bar'];
        $encoded = JWT::encode($payload, $privateKey, $alg);

        // Verify decoding succeeds
        $publicKey = file_get_contents($publicKeyFile);
        $decoded = JWT::decode($encoded, new Key($publicKey, $alg));

        $this->assertSame('bar', $decoded->foo);
    }

    public function provideEncodeDecode()
    {
        return [
            [__DIR__ . '/data/ecdsa-private.pem', __DIR__ . '/data/ecdsa-public.pem', 'ES256'],
            [__DIR__ . '/data/ecdsa384-private.pem', __DIR__ . '/data/ecdsa384-public.pem', 'ES384'],
            [__DIR__ . '/data/rsa1-private.pem', __DIR__ . '/data/rsa1-public.pub', 'RS512'],
            [__DIR__ . '/data/ed25519-1.sec', __DIR__ . '/data/ed25519-1.pub', 'EdDSA'],
            [__DIR__ . '/data/secp256k1-private.pem', __DIR__ . '/data/secp256k1-public.pem', 'ES256K'],
        ];
    }

    public function testEncodeDecodeWithResource()
    {
        $pem = file_get_contents(__DIR__ . '/data/rsa1-public.pub');
        $resource = openssl_pkey_get_public($pem);
        $privateKey = file_get_contents(__DIR__ . '/data/rsa1-private.pem');

        $payload = ['foo' => 'bar'];
        $encoded = JWT::encode($payload, $privateKey, 'RS512');

        // Verify decoding succeeds
        $decoded = JWT::decode($encoded, new Key($resource, 'RS512'));

        $this->assertSame('bar', $decoded->foo);
    }
 */
}

  // https://roytuts.com/how-to-generate-and-validate-jwt-using-php-without-using-third-party-api/

    function generate_jwt($headers, $payload, $secret = 'secret') {
        $headers_encoded = base64url_encode(json_encode($headers));
        
        $payload_encoded = base64url_encode(json_encode($payload));
        
        $signature = hash_hmac('SHA256', "$headers_encoded.$payload_encoded", $secret, true);
        $signature_encoded = base64url_encode($signature);
        
        $jwt = "$headers_encoded.$payload_encoded.$signature_encoded";
        
        return $jwt;
    }
    
    function base64url_encode($str) {
        return rtrim(strtr(base64_encode($str), '+/', '-_'), '=');
    }

    function is_jwt_valid($jwt, $secret = 'secret') {
        // split the jwt
        $tokenParts = explode('.', $jwt);
        $header = base64_decode($tokenParts[0]);
        $payload = base64_decode($tokenParts[1]);
        $signature_provided = $tokenParts[2];

        echo "header= $header\n";
        echo "alg= ".json_decode($header)->alg."\n";
        echo "typ= ".json_decode($header)->typ."\n";

        echo "payload= $payload\n";
        echo "sub= ".json_decode($payload)->sub."\n";
        echo "name= ".json_decode($payload)->name."\n";
        echo "admin= ".json_decode($payload)->admin."\n";
        echo "exp= ".json_decode($payload)->exp."\n";

        echo "signature_provided= $signature_provided\n";


        // check the expiration time - note this will cause an error if there is no 'exp' claim in the jwt
        $expiration = json_decode($payload)->exp;
        $is_token_expired = ($expiration - time()) < 0;

        // build a signature based on the header and payload using the secret
        $base64_url_header = base64url_encode($header);
        $base64_url_payload = base64url_encode($payload);
        $signature = hash_hmac('SHA256', $base64_url_header . "." . $base64_url_payload, $secret, true);
        $base64_url_signature = base64url_encode($signature);

        // verify it matches the signature provided in the jwt
        $is_signature_valid = ($base64_url_signature === $signature_provided);
        
        return [$is_signature_valid, $is_token_expired];
    }
