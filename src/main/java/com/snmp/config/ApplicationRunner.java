/*
package com.snmp.config;

import com.snmp.util.SNMPTrapHandler;
import org.snmp4j.mp.SnmpConstants;
import org.springframework.boot.ApplicationArguments;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

@Component
@Order(value = 1)
public class ApplicationRunner implements org.springframework.boot.ApplicationRunner {

    @Override
    public void run(ApplicationArguments args) throws Exception {
        SNMPTrapHandler trapReceiver = new SNMPTrapHandler(
                "172.16.1.37", 162, SnmpConstants.version3, "public");
    }
}
*/
