const axios = require('axios');
const { DOMParser } = require('xmldom');


function binarySecurityToken() {
    const xmlData = `<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:eb="http://www.ebxml.org/namespaces/messageHeader" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:xsd="http://www.w3.org/1999/XMLSchema">
    <SOAP-ENV:Header>
      <eb:MessageHeader SOAP-ENV:mustUnderstand="1" eb:version="1.0">
        <eb:From>
          <eb:PartyId type="urn:x12.org:IO5:01">www.sabreng.com</eb:PartyId>
        </eb:From>
        <eb:To>
          <eb:PartyId type="urn:x12.org:IO5:01">https://webservices.cert.platform.sabre.com</eb:PartyId>
        </eb:To>
        <eb:CPAId>WD4H</eb:CPAId>
        <eb:ConversationId>api@sabreng.com</eb:ConversationId>
        <eb:Service eb:type="string">SessionCreateRequest</eb:Service>
        <eb:Action>SessionCreateRQ</eb:Action>
        <eb:MessageData>
          <eb:MessageId>1000</eb:MessageId>
          <eb:Timestamp>2024-04-19T016:58:00Z</eb:Timestamp>
          <eb:TimeToLive>2024-04-26T16:58:00Z</eb:TimeToLive>
        </eb:MessageData>
      </eb:MessageHeader>
      <wsse:Security xmlns:wsse="http://schemas.xmlsoap.org/ws/2002/12/secext">
        <wsse:UsernameToken>
          <wsse:Username>937184</wsse:Username>
          <wsse:Password>WS20WS24</wsse:Password>
          <wsse:Organization>WD4H</wsse:Organization>
          <wsse:Domain>DEFAULT</wsse:Domain>
        </wsse:UsernameToken>
      </wsse:Security>
    </SOAP-ENV:Header>
    <SOAP-ENV:Body>
      <SessionCreateRQ xmlns="http://www.opentravel.org/OTA/2002/11">
        <POS>
          <Source PseudoCityCode="WD4H" />
        </POS>
      </SessionCreateRQ>
    </SOAP-ENV:Body>
    </SOAP-ENV:Envelope>`;

    const config = {
    method: 'post',
    maxBodyLength: Infinity,
    url: 'https://webservices.cert.platform.sabre.com/',
    headers: {
      'Content-Type': 'text/xml; charset=utf-8',
    },
    data: xmlData,
    };

    return new Promise((resolve, reject) => {
        axios.request(config)
          .then((response) => {
              const xmlResponse = response.data;
              const parser = new DOMParser();
              const xmlDoc = parser.parseFromString(xmlResponse, 'text/xml');
              const securityNode = xmlDoc.getElementsByTagName('wsse:Security')[0];
              const binarySecurityTokenNode = securityNode.getElementsByTagName('wsse:BinarySecurityToken')[0];
              const binarySecurityToken = binarySecurityTokenNode.textContent;
              resolve(binarySecurityToken);
          })
          .catch((error) => {
              reject(error);
          });
    });
}    

module.exports = binarySecurityToken;