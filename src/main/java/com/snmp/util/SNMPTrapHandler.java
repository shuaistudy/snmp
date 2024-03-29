package com.snmp.util;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.snmp4j.*;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultTcpTransportMapping;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.MultiThreadedMessageDispatcher;
import org.snmp4j.util.ThreadPool;

import java.io.IOException;
import java.util.Vector;

/**
 * Description:
 *      SNMP Trap多线程接收解析信息
 */
public class SNMPTrapHandler implements CommandResponder {

    private final static Logger log =  LoggerFactory.getLogger(SNMPTrapHandler.class);

    private MultiThreadedMessageDispatcher dispatcher;
    private Snmp snmp = null;
    private Address listenAddress;
    private ThreadPool threadPool;
    private int version;
    private String host;
    private int port;
    private String community;


    public SNMPTrapHandler(String host, int port, int version, String community) {
        this.host = host;
        this.port = port;
        this.version = version;
        this.community = community;

        try {
            listen();
        } catch (IOException e) {
            e.printStackTrace();
        }
        snmp.addCommandResponder(this);
        log.info("---- Trap Receiver is listening the trap message  ----");
    }

    private void listen() throws IOException {
        threadPool = ThreadPool.create("SnmpTrap", 3);
        dispatcher = new MultiThreadedMessageDispatcher(threadPool, new MessageDispatcherImpl());
        listenAddress = new UdpAddress(host + "/" + port);
        TransportMapping transport;
        if (listenAddress instanceof UdpAddress) {
            transport = new DefaultUdpTransportMapping((UdpAddress) listenAddress);
        } else {
            transport = new DefaultTcpTransportMapping((TcpAddress) listenAddress);
        }
        snmp = new Snmp(dispatcher, transport);
        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv1());
        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv2c());
        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv3());

        if (version == SnmpConstants.version3) {
            USM usm = new USM(
                    SecurityProtocols.getInstance().addDefaultProtocols(),
                    new OctetString(MPv3.createLocalEngineID()), 0);
            usm.setEngineDiscoveryEnabled(true);
            SecurityModels.getInstance().addSecurityModel(usm);
            //TODO 添加服务器上管理的V3用户，暂时只添加一个snmpuser测试用户
            snmp.getUSM().addUser(
                    new OctetString("snmpuser"),
                    new UsmUser(new OctetString("snmpuser"), AuthMD5.ID,
                            new OctetString("auth123456"), PrivDES.ID,
                            new OctetString("priv123456")));
            SecurityModels.getInstance().addSecurityModel(usm);
        }

        snmp.listen();
    }


    public void processPdu(CommandResponderEvent event) {
        log.info("---- Begin ----");
        if (event == null || event.getPDU() == null) {
            log.info("ResponderEvent or PDU is null!");
            return;
        }
        Vector<? extends VariableBinding> vbs = event.getPDU().getVariableBindings();
        for (VariableBinding vb : vbs) {
            String key=vb.getOid().toString();
            String value=vb.getVariable().toString();
            System.out.println(key + " = " + value);
        }
        log.info("---- End ----");
    }

}
