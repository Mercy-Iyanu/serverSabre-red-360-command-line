const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const axios = require('axios');
const jwt = require('jsonwebtoken')
const app = express();
const PORT = process.env.PORT || 4000;
const { DOMParser } = require('xmldom');

let securityToken = ''; 

app.use(cors());
app.use(bodyParser.json());

const getSecurityToken = async (req, res, next) => {
  try {
    const xmlData = `
      <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:eb="http://www.ebxml.org/namespaces/messageHeader" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:xsd="http://www.w3.org/1999/XMLSchema" xmlns:wsse="http://schemas.xmlsoap.org/ws/2002/12/secext">
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
              <eb:Timestamp>2024-04-24T016:58:00Z</eb:Timestamp>
              <eb:TimeToLive>2024-05-26T16:58:00Z</eb:TimeToLive>
            </eb:MessageData>
          </eb:MessageHeader>
          <wsse:Security>
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

    const response = await axios.request(config);
    const xmlResponse = response.data;

    const parser = new DOMParser();
    const xmlDoc = parser.parseFromString(xmlResponse, 'text/xml');

    const securityNode = xmlDoc.getElementsByTagName('wsse:Security')[0];
    const binarySecurityTokenNode = securityNode.getElementsByTagName('wsse:BinarySecurityToken')[0];

    securityToken = binarySecurityTokenNode.textContent;
    console.log(binarySecurityTokenNode);

    next();
  } catch (error) {
    console.error('Error fetching security token:', error);
    res.status(500).json({ error: 'Failed to fetch security token' });
  }
};

app.use(getSecurityToken);

const constructRequestWithToken = (xmlData) => {
  return `
    ${xmlData}
    <SOAP-ENV:Header>
      <wsse:Security xmlns:wsse="http://schemas.xmlsoap.org/ws/2002/12/secext" xmlns:wsu="http://schemas.xmlsoap.org/ws/2002/12/utility">
        <wsse:BinarySecurityToken valueType="String" EncodingType="wsse:Base64Binary">${securityToken}</wsse:BinarySecurityToken>
      </wsse:Security>
    </SOAP-ENV:Header>
  `;
};


app.post('/api/sabre', async (req, res) => {
  const requestData = `
    <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:eb="http://www.ebxml.org/namespaces/messageHeader" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:xsd="http://www.w3.org/1999/XMLSchema" xmlns:wsse="http://schemas.xmlsoap.org/ws/2002/12/secext">
      ${constructRequestWithToken(`
        <SOAP-ENV:Header>
          <eb:MessageHeader SOAP-ENV:mustUnderstand="1" eb:version="1.0">
            <eb:ConversationId>LRQ</eb:ConversationId>
            <eb:From>
              <eb:PartyId type="urn:x12.org:IO5:01">99999</eb:PartyId>
            </eb:From>
            <eb:To>
              <eb:PartyId type="urn:x12.org:IO5:01">123123</eb:PartyId>
            </eb:To>
            <eb:CPAId>WD4H</eb:CPAId>
            <eb:Service eb:type="OTA">SabreCommandLLSRQ</eb:Service>
            <eb:Action>SabreCommandLLSRQ</eb:Action>
            <eb:MessageData>
              <eb:MessageId>5590918583883411930</eb:MessageId>
              <eb:Timestamp>2024-04-24T11:28:41</eb:Timestamp>
              <eb:TimeToLive>2024-04-26T11:28:41</eb:TimeToLive>
            </eb:MessageData>
          </eb:MessageHeader>
        </SOAP-ENV:Header>
        <SOAP-ENV:Body>
          <SabreCommandLLSRQ EchoToken="String" TimeStamp="2001-12-17T09:30:47-05:00" Target="Production" Version="2003A.TsabreXML1.5.1" SequenceNmbr="1" PrimaryLangID="en-us" AltLangID="en-us" xmlns="http://webservices.sabre.com/sabreXML/2003/07" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Request Output="SCREEN" CDATA="true">
              <HostCommand>${req.body.inputText}</HostCommand>
            </Request>
          </SabreCommandLLSRQ>
        </SOAP-ENV:Body>
      `)}
    </SOAP-ENV:Envelope>
  `;

  try {
    const config = {
      method: 'post',
      maxBodyLength: Infinity,
      url: 'https://webservices.cert.platform.sabre.com/',
      headers: {
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': 'SabreCommandLLSRQ',
        'Cookie': 'visid_incap_1446254=QKVpJ8AnRqO71Wii3W/Cwkiy8WUAAAAAQUIPAAAAAABXG9MIr/A4ETFutxLub+sl; visid_incap_2768614=tU7GpZ1qSw+QqEKT7WB+f+oh72UAAAAAQUIPAAAAAAAsCMzgRUxuU3LitB2oOYcT'
      },
      data: requestData,
    };

    const response = await axios.request(config);
    console.log(response.data)
    res.send(response.data);
  } catch (error) {
    console.error('Error sending Sabre command:', error);
    res.status(500).json({ error: 'Failed to send Sabre command' });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});