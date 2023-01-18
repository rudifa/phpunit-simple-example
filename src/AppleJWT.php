<?php

namespace drmonkeyninja;

class AppleJWT {

    // string received over the wire
    public $signedPayloadDict;

    // the value of the signedPayload key
    public $signedPayload;

    // the 3 parts of the signedPayload
    public $signedPayloadParts;

    public $signedPayload_header;
    public $signedPayload_payload;
    public $signedPayload_signature_provided;

    // the header of the signedPayload
    public $signedPayload_header_alg;
    public $signedPayload_header_x5c;

    // the x5c array of the header: 3 parts
    public $signedPayload_header_x5c_header;
    public $signedPayload_header_x5c_payload;
    public $signedPayload_header_x5c_signature_provided;

    // the 3 parts of header xc5 decoded
    public $signedPayload_header_x5c_header_0;
    public $signedPayload_header_x5c_header_1;
    public $signedPayload_header_x5c_header_2;

    // the first 3 values in signedPayload_payload
    public $signedPayload_payload_notificationType;
    public $signedPayload_payload_subtype;
    public $signedPayload_payload_notificationUUID;
    public $signedPayload_payload_data;
    public $signedPayload_payload_version;
    public $signedPayload_payload_signedDate;

    // items from $signedPayload_payload_data;
    public $signedPayload_payload_data_bundleId;
    public $signedPayload_payload_data_bundleVersion;
    public $signedPayload_payload_data_environment;
    public $signedPayload_payload_data_signedTransactionInfo; // is a signed string 

    public $signedPayload_payload_data_signedTransactionInfo_parts; // is an array of 3 parts

    public $signedPayload_payload_data_signedTransactionInfo_part_1; // part  of interest

    // 14 extracted items
    public $signedPayload_payload_data_signedTransactionInfo_part_1_transactionId;
    public $signedPayload_payload_data_signedTransactionInfo_part_1_originalTransactionId;
    public $signedPayload_payload_data_signedTransactionInfo_part_1_webOrderLineItemId;

    public $signedPayload_payload_data_signedTransactionInfo_part_1_bundleId;
    public $signedPayload_payload_data_signedTransactionInfo_part_1_productId;
    public $signedPayload_payload_data_signedTransactionInfo_part_1_subscriptionGroupIdentifier;

    public $signedPayload_payload_data_signedTransactionInfo_part_1_purchaseDate;
    public $signedPayload_payload_data_signedTransactionInfo_part_1_originalPurchaseDate;
    public $signedPayload_payload_data_signedTransactionInfo_part_1_expiresDate;

    public $signedPayload_payload_data_signedTransactionInfo_part_1_quantity;
    public $signedPayload_payload_data_signedTransactionInfo_part_1_type;
    public $signedPayload_payload_data_signedTransactionInfo_part_1_inAppOwnershipType;

    public $signedPayload_payload_data_signedTransactionInfo_part_1_signedDate;
    public $signedPayload_payload_data_signedTransactionInfo_part_1_environment;




    public function __construct(string $signedPayloadDict) {

        // 1. initialize the signedPayloadDict property from the constructor argument
        $this->signedPayloadDict = $signedPayloadDict;

        // 2. extract the value of the signedPayload key
        $this->signedPayload = json_decode($this->signedPayloadDict)->signedPayload;

        // 3. split the signedPayload into three parts on '.'
        $this->signedPayloadParts = explode('.', $this->signedPayload);

        // 4. decode the 3 part ofs the signedPayload
        $this->signedPayload_header = base64_decode($this->signedPayloadParts[0]);
        $this->signedPayload_payload = base64_decode($this->signedPayloadParts[1]);
        $this->signedPayload_signature_provided = base64_decode($this->signedPayloadParts[2]);

        // 5. decode the header and payload
        $this->signedPayload_header_alg = json_decode($this->signedPayload_header)->alg;
        $this->signedPayload_header_x5c = json_decode($this->signedPayload_header)->x5c; // this is an array

        // // 6. separate the x5c array into parts and decode each part
        $this->signedPayload_header_x5c_header = base64_decode($this->signedPayload_header_x5c[0]);
        $this->signedPayload_header_x5c_payload = base64_decode($this->signedPayload_header_x5c[1]);
        $this->signedPayload_header_x5c_signature_provided = $this->signedPayload_header_x5c[2];

        // 7. decode the x5c header parts 0, 1, 2
        $this->signedPayload_header_x5c_header_0 = json_decode($this->signedPayload_header_x5c_header[0]);
        $this->signedPayload_header_x5c_header_1 = json_decode($this->signedPayload_header_x5c_header[1]);
        $this->signedPayload_header_x5c_header_2 = json_decode($this->signedPayload_header_x5c_header[2]);

        // 8. decode the signedPayload_payload values
        $this->signedPayload_payload_notificationType = json_decode($this->signedPayload_payload)->notificationType;
        $this->signedPayload_payload_subtype = json_decode($this->signedPayload_payload)->subtype;
        $this->signedPayload_payload_notificationUUID = json_decode($this->signedPayload_payload)->notificationUUID;


        $this->signedPayload_payload_data = json_decode($this->signedPayload_payload)->data; // is stdClass

        $this->signedPayload_payload_data_bundleId = $this->signedPayload_payload_data->bundleId;

        $this->signedPayload_payload_data_bundleVersion = $this->signedPayload_payload_data->bundleVersion;

        $this->signedPayload_payload_data_environment = $this->signedPayload_payload_data->environment;
        $this->signedPayload_payload_data_signedTransactionInfo = $this->signedPayload_payload_data->signedTransactionInfo;

        // split the signedTransactionInfo into 3 parts
        $this->signedPayload_payload_data_signedTransactionInfo_parts = explode('.', $this->signedPayload_payload_data_signedTransactionInfo);

        $this->signedPayload_payload_data_signedTransactionInfo_part_1 = base64_decode($this->signedPayload_payload_data_signedTransactionInfo_parts[1]);


        // 9. extract 14 items from signedPayload_payload_data_signedTransactionInfo_part_1

        $this->signedPayload_payload_data_signedTransactionInfo_part_1_transactionId  = json_decode($this->signedPayload_payload_data_signedTransactionInfo_part_1)->transactionId;
        $this->signedPayload_payload_data_signedTransactionInfo_part_1_originalTransactionId  = json_decode($this->signedPayload_payload_data_signedTransactionInfo_part_1)->originalTransactionId;
        $this->signedPayload_payload_data_signedTransactionInfo_part_1_webOrderLineItemId  = json_decode($this->signedPayload_payload_data_signedTransactionInfo_part_1)->webOrderLineItemId;

        $this->signedPayload_payload_data_signedTransactionInfo_part_1_bundleId  = json_decode($this->signedPayload_payload_data_signedTransactionInfo_part_1)->bundleId;
        $this->signedPayload_payload_data_signedTransactionInfo_part_1_productId  = json_decode($this->signedPayload_payload_data_signedTransactionInfo_part_1)->productId;
        $this->signedPayload_payload_data_signedTransactionInfo_part_1_subscriptionGroupIdentifier  = json_decode($this->signedPayload_payload_data_signedTransactionInfo_part_1)->subscriptionGroupIdentifier;

        $this->signedPayload_payload_data_signedTransactionInfo_part_1_purchaseDate  = json_decode($this->signedPayload_payload_data_signedTransactionInfo_part_1)->purchaseDate;
        $this->signedPayload_payload_data_signedTransactionInfo_part_1_originalPurchaseDate  = json_decode($this->signedPayload_payload_data_signedTransactionInfo_part_1)->originalPurchaseDate;
        $this->signedPayload_payload_data_signedTransactionInfo_part_1_expiresDate  = json_decode($this->signedPayload_payload_data_signedTransactionInfo_part_1)->expiresDate;

        $this->signedPayload_payload_data_signedTransactionInfo_part_1_quantity  = json_decode($this->signedPayload_payload_data_signedTransactionInfo_part_1)->quantity;
        $this->signedPayload_payload_data_signedTransactionInfo_part_1_type  = json_decode($this->signedPayload_payload_data_signedTransactionInfo_part_1)->type;
        $this->signedPayload_payload_data_signedTransactionInfo_part_1_inAppOwnershipType  = json_decode($this->signedPayload_payload_data_signedTransactionInfo_part_1)->inAppOwnershipType;

        $this->signedPayload_payload_data_signedTransactionInfo_part_1_signedDate  = json_decode($this->signedPayload_payload_data_signedTransactionInfo_part_1)->signedDate;
        $this->signedPayload_payload_data_signedTransactionInfo_part_1_environment  = json_decode($this->signedPayload_payload_data_signedTransactionInfo_part_1)->environment;

    } 
}
