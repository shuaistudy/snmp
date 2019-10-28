package com.snmp.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.event.ResponseListener;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.DefaultPDUFactory;

import java.io.IOException;
import java.util.*;

/**
 * Description: 根据SNMP协议编写的SNMP常用操作:
 *
 *  1.get-request 操作: 从代理进程处提取一个或多个参数值,只查询MIB的叶子节点
 *  2.getNext-request 操作: 从代理进程处提取紧跟当前参数值的下一个参数值
 *  3.getBulk-request 操作: 会根据最大重试值执行一个连续的getNext操作,该操作常用于查询数据量较大的场景,提高效率
 *  4.set-request 操作: 设置代理进程的一个或多个参数值
 *  5.get-response 操作: 这个操作是由代理进程发出的,它是上述四种操作的响应
 *  6.inform-request 操作:
 *  7.report 操作:
 *  8.trap 操作: 代理进程主动发出的报文,通知管理进程有某些事情发生
 *
 */
public class SNMPQuery {

    private final static Logger log =  LoggerFactory.getLogger(SNMPTrapHandler.class);
    private static final String ROOT = "WALK";

    private static Map<String,String> datas;
    private static Snmp snmp = null;

    private static String host;
    private static int port;
    private static int version;
    private static String community;
    private static Target target;

    private static String securityName="snmpuser";
    private static String authPassword="auth123456";
    private static String privPassword="priv123456";
    private static String privProtocol="DES";
    private static String authProtocol="MD5";
    private static int securityLevel=SecurityLevel.AUTH_PRIV;
    private static OID priProtocolBean;
    private  OID authProtocolBean;

  //  public SNMPQuery(String host) { this(host, 161); }

    public SNMPQuery(String host, int port) {
        this(host, port, SnmpConstants.version2c);
    }

    public SNMPQuery(String host, int port, int version) {
        this(host, port, version, "public");
    }

    public SNMPQuery(String host, int port, int version, String community) {
        this.host = host;
        this.port = port;
        this.version = version;
        this.community = community;
        initSNMP(version);
        createTarget(host, port, version, community);
    }

    public  void initSNMP(int version) {
        try {
            TransportMapping transport = new DefaultUdpTransportMapping();
            snmp = new Snmp(transport);
            if (version == SnmpConstants.version3) {
                USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(MPv3.createLocalEngineID()), 0);
                SecurityModels.getInstance().addSecurityModel(usm);
            }
            transport.listen();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public  void createTarget(String host, int port, int version, String community) {
        //Address targetAddress = GenericAddress.parse("udp:"+bindHost+"/"+bindPort);
        Address targetAddress = new UdpAddress(host + "/" + port);

        if (version == SnmpConstants.version3) {

            setPriProtocolBean(privProtocol);
            setAuthProtocolBean(authProtocol);

            snmp.getUSM().addUser(new OctetString(securityName)
                    , new UsmUser(
                            new OctetString(securityName)
                            , authProtocolBean
                            , new OctetString(authPassword)
                            , priProtocolBean
                            , new OctetString(privPassword)));
            target = new UserTarget();
            //SecurityLevel: NOAUTH_NOPRIV | AUTH_NOPRIV | AUTH_PRIV
            target.setSecurityLevel(securityLevel);
            target.setSecurityName(new OctetString(securityName));
            target.setVersion(SnmpConstants.version3);
        } else {
            target = new CommunityTarget();
            if (version == SnmpConstants.version1) {
                ((CommunityTarget) target).setCommunity(new OctetString(community));
                target.setVersion(SnmpConstants.version1);
            } else {
                ((CommunityTarget)target).setCommunity(new OctetString(community));
                target.setVersion(SnmpConstants.version2c);
            }

        }
        target.setAddress(targetAddress);
        target.setRetries(3);
        target.setTimeout(1000);
    }

    private  void setPriProtocolBean(String privProtocol) {
        if (privProtocol.equalsIgnoreCase("des"))
            priProtocolBean = PrivDES.ID;
        else if (privProtocol.equalsIgnoreCase("aes128")
                || privProtocol.equalsIgnoreCase("aes"))
            priProtocolBean = PrivAES128.ID;
        else if (privProtocol.equalsIgnoreCase("aes192"))
            priProtocolBean = PrivAES192.ID;
        else if (privProtocol.equalsIgnoreCase("aes256"))
            priProtocolBean = PrivAES256.ID;
        else
            priProtocolBean = null;
    }

    private  void setAuthProtocolBean(String authProtocol) {
        if (authProtocol.equalsIgnoreCase("md5"))
            authProtocolBean = AuthMD5.ID;
        else if (authProtocol.equalsIgnoreCase("sha"))
            authProtocolBean = AuthSHA.ID;
        else
            authProtocolBean = null;
    }

    public  PDU createPDU(int pduType) {
        PDU pdu;
        switch (version) {
            case SnmpConstants.version3: {
                pdu = new ScopedPDU();
                break;
            }
            case SnmpConstants.version1: {
                pdu = new PDUv1();
                break;
            }
            default:
                pdu = new PDU();
        }
        pdu.setType(pduType);
        return pdu;
    }

    private  class MyDefaultPDUFactory extends DefaultPDUFactory {
        private OctetString contextEngineId = null;

        public MyDefaultPDUFactory(int pduType, OctetString contextEngineId) {
            super(pduType);
            this.contextEngineId = contextEngineId;
        }

        @Override
        public PDU createPDU(Target target) {
            PDU pdu = super.createPDU(target);
            if (target.getVersion() == SnmpConstants.version3) {
                ((ScopedPDU)pdu).setContextEngineID(contextEngineId);
            }
            return pdu;
        }
    }

    public  void snmpGet(String oid) throws Exception {
        snmpGet(Arrays.asList(oid));
    }

    public  void snmpGet(List<String> oids) throws Exception {

        Map<String, String> datas = new HashMap<String, String>();
        PDU pdu = createPDU(PDU.GET);
        for (String oid : oids) {
            if (oid.endsWith(".0")) {
                pdu.add(new VariableBinding(new OID(oid)));
            } else {
                //throw new IllegalArgumentException(oid + ": 为MIB中非叶子节点，请检查！");
            }
        }

        ResponseEvent respEvent = snmp.get(pdu, target);
        PDU response = respEvent.getResponse();
        //解析response
        if(respEvent != null && response != null){
//            if (response.getErrorIndex() == PDU.noError && response.getErrorStatus() == PDU.noError) {
                Vector<? extends VariableBinding> vector = response.getVariableBindings();
                for (VariableBinding vb : vector) {
                    String key = vb.getOid().toString();
                    datas.put(key, vb.getVariable().toString());
                }
//            } else {
//                throw new Exception("Error:{} " + response.getErrorStatusText());
//            }
        }

        log.info("Snmp get-request operation and the data is : " + datas);
    }


    public  void snmpWalk(OID oid, String type) throws Exception {
        if (type.equals(SNMPQuery.ROOT)) {
            type = oid.toString();
        }
        datas=new HashMap<String, String>();
        PDU pdu = createPDU(PDU.GETNEXT);
        pdu.add(new VariableBinding(oid));
        ResponseEvent rspEvt = snmp.send(pdu, target);
        PDU response = rspEvt.getResponse();

        if (response.getErrorIndex() == PDU.noError && response.getErrorStatus() == PDU.noError) {
            VariableBinding vb = (VariableBinding) response.getVariableBindings().firstElement();
            OID curr_oid = vb.getOid();
            String curr_str = curr_oid.toString();
            if (curr_str.contains(type)) {//判断获得的值是否是指定根节点下面
                String key = vb.getOid().toString();
                datas.put(key.replace(type, ""), vb.getVariable().toString());
                log.info("Snmp getNext-request operation and the data is :" + datas);
                snmpWalk(curr_oid, type);
            }
        } else {
            throw new Exception("Error message:{} " + response.getErrorStatusText());
        }
    }

    public  void snmpSet(OID oid, Variable newVar) throws Exception {
        PDU request = createPDU(PDU.SET);
        request.add(new VariableBinding(oid, newVar));
        ResponseEvent resEvt = snmp.send(request, target);
        PDU response = resEvt.getResponse();
        if (response.getErrorIndex() == PDU.noError && response.getErrorStatus() == PDU.noError) {
            VariableBinding vb = (VariableBinding) response.getVariableBindings().firstElement();
            Variable var = vb.getVariable();
            if (var.equals(newVar)) {//比较返回值和设置值
                log.info("Set operation is successful !");
            } else {
                log.info("Snmp set operation is fail !");
            }
        } else {
            throw new Exception("Error info :{} " + response.getErrorStatusText());
        }
    }

    public  ResponseEvent sendSnmpTrap(String oid) throws IOException {
        return sendSnmpTrap(Arrays.asList(oid));
    }

    //support snmp v1|v2c|v3
    public  ResponseEvent sendSnmpTrap(List<String> oids) throws IOException {
        PDU pdu ;
        if(version==SnmpConstants.version1){
            pdu=createPDU(PDU.V1TRAP);
        } else{
            pdu=createPDU(PDU.TRAP);
        }
        for (String oid : oids) {
            if (oid.endsWith(".0")) {
                pdu.add(new VariableBinding(new OID(oid),new OctetString("SNMP Trap Test.")));
            } else {
                throw new IllegalArgumentException(oid + ": 为MIB中非叶子节点，请检查！");
            }
        }
        return snmp.set(pdu,target);
    }

    public  void snmpGetResponse(Boolean syn, final Boolean bro, String oid) throws IOException {
        snmpGetResponse(syn, bro, Arrays.asList(oid));
    }

    public  void snmpGetResponse(Boolean syn, final Boolean bro, List<String> oids) throws IOException {
        PDU pdu = createPDU(PDU.GET);
        for (String oid : oids) {
            pdu.addOID(new VariableBinding(new OID(oid)));
        }
        if (!syn) {
            ResponseEvent response = snmp.send(pdu, target);

            log.info(
                    "Synchronize message from:{} " + response.getPeerAddress() + System.getProperty("line.separator")
                            + "request:{} " + response.getRequest() + System.getProperty("line.separator")
                            + "response:{} " + response.getResponse() + System.getProperty("line.separator")
                            + "get object:{} " + response.getUserObject() + System.getProperty("line.separator"));
        } else {
            ResponseListener listener = new ResponseListener() {

                @Override
                public void onResponse(ResponseEvent event) {
                    if (bro.equals(false)) {
                        ((Snmp) event.getSource()).cancel(event.getRequest(), this);
                    }

                    PDU request = event.getRequest();
                    PDU response = event.getResponse();
                    log.info(
                            "Asynchronise message from:{} " + event.getPeerAddress() + System.getProperty("line.separator")
                                    + "request:{} " + request + System.getProperty("line.separator")
                                    + "response:{} " + response.toString());
                }
            };
            snmp.send(pdu, target, null, listener);
        }
    }

    public void destory(){
        if(snmp!=null){
            try {
                snmp.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

}