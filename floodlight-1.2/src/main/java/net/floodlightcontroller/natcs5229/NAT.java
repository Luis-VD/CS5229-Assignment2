package net.floodlightcontroller.natcs5229;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IListener;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.packet.*;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.util.FlowModUtils;
import org.kohsuke.args4j.CmdLineException;
import org.projectfloodlight.openflow.protocol.*;
import java.io.IOException;
import java.util.*;
import net.floodlightcontroller.core.IFloodlightProviderService;
import java.util.concurrent.ConcurrentSkipListSet;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.*;
import org.python.modules._hashlib;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Created by pravein on 28/9/17.
 */
public class NAT implements IOFMessageListener, IFloodlightModule {

    protected IFloodlightProviderService floodlightProvider;
    protected Set<Long> macAddresses;
    protected static Logger logger;

    HashMap<String, String> RouterInterfaceMacMap = new HashMap<>();
    HashMap<Integer, String> IPTransMap = new HashMap<>();
    HashMap<String, OFPort> IPPortMap = new HashMap<>();
    HashMap<String, String> IPMacMap = new HashMap<>();


    @Override
    public String getName() {
        return NAT.class.getName();
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        return false;
    }





    // Main Place to Handle PacketIN to perform NAT
    private Command handlePacketIn(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		IPacket pkt = eth.getPayload();
	if (eth.isBroadcast() || eth.isMulticast()){
	
		if (pkt instanceof ARP){
			ARP arpRequest = (ARP) eth.getPayload();
			IPv4Address targetProtocolAddress = arpRequest.getTargetProtocolAddress();
			String srcIp = arpRequest.getSenderProtocolAddress().toString();

			logger.info("Getting ARP for: " + targetProtocolAddress.toString());

			logger.info("Requestor : " + srcIp + " from : " + pi.getMatch().get(MatchField.IN_PORT).getPortNumber());

			proxyArpReply(sw, pi, cntx);
			return Command.STOP;


		}
	} else{
		if (pkt instanceof IPv4){
			IPv4 ip_pkt = (IPv4) pkt;
			
			byte[] ipOptions = ip_pkt.getOptions();
			IPv4Address dstIp = ip_pkt.getDestinationAddress();

			if (ip_pkt.getProtocol() == IpProtocol.TCP) {
				/* We got a TCP packet; get the payload from IPv4 */
				TCP tcp = (TCP) ip_pkt.getPayload();
				
				/* Various getters and setters are exposed in TCP */
				TransportPort srcPort = tcp.getSourcePort();
				TransportPort dstPort = tcp.getDestinationPort();
				short flags = tcp.getFlags();
				 
				/* Your logic here! */
			} else if (ip_pkt.getProtocol() == IpProtocol.UDP) {
				/* We got a UDP packet; get the payload from IPv4 */
				UDP udp = (UDP) ip_pkt.getPayload();
				
				/* Various getters and setters are exposed in UDP */
				TransportPort srcPort = udp.getSourcePort();
				TransportPort dstPort = udp.getDestinationPort();
				 
				/* Your logic here! */
	            }

		}
	}



	return Command.CONTINUE;
    }

    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        switch(msg.getType()) {
            case PACKET_IN:
                return handlePacketIn(sw, (OFPacketIn)msg, cntx);
            default:
                break;
        }
        logger.warn("Received unexpected message {}", msg);
        return Command.CONTINUE;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        return null;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l =
                new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        macAddresses = new ConcurrentSkipListSet<Long>();
        logger = LoggerFactory.getLogger(NAT.class);

        // Use the below HashMaps as per your need

        // Router Interface IP to Mac address Mappings
        RouterInterfaceMacMap.put("10.0.0.1","00:23:10:00:00:01");
        RouterInterfaceMacMap.put("192.168.0.1","00:23:10:00:00:02");
        RouterInterfaceMacMap.put("192.168.0.2","00:23:10:00:00:03");

        // IP to Router Interface mappings
        IPPortMap.put("192.168.0.10", OFPort.of(1));
        IPPortMap.put("192.168.0.20", OFPort.of(2));
        IPPortMap.put("10.0.0.11", OFPort.of(3));

        //Client/Server ip to Mac mappings
        IPMacMap.put("192.168.0.10", "00:00:00:00:00:01");
        IPMacMap.put("192.168.0.20", "00:00:00:00:00:02");
        IPMacMap.put("10.0.0.11", "00:00:00:00:00:03");
    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
    }


	//Extra Code here:


	protected void proxyArpReply(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
		logger.info("ProxyArpReply");

		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

		// retrieve original arp to determine host configured gw IP address
		if (! (eth.getPayload() instanceof ARP))
			return;
		ARP arpRequest = (ARP) eth.getPayload();

		// have to do proxy arp reply since at this point we cannot determine the requesting application type

		// generate proxy ARP reply
		IPacket arpReply = new Ethernet()
				.setSourceMACAddress(eth.getDestinationMACAddress())
				.setDestinationMACAddress(eth.getSourceMACAddress())
				.setEtherType(EthType.ARP)
				.setVlanID(eth.getVlanID())
				.setPriorityCode(eth.getPriorityCode())
				.setPayload(
						new ARP()
								.setHardwareType(ARP.HW_TYPE_ETHERNET)
								.setProtocolType(ARP.PROTO_TYPE_IP)
								.setHardwareAddressLength((byte) 6)
								.setProtocolAddressLength((byte) 4)
								.setOpCode(ARP.OP_REPLY)
								.setSenderHardwareAddress(eth.getDestinationMACAddress())
								.setSenderProtocolAddress(arpRequest.getTargetProtocolAddress())
								.setTargetHardwareAddress(eth.getSourceMACAddress())
								.setTargetProtocolAddress(arpRequest.getSenderProtocolAddress()));

		// push ARP reply out
		pushPacket(arpReply, sw, OFBufferId.NO_BUFFER, OFPort.ANY, (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT)), cntx, true);
		logger.info("proxy ARP reply pushed as {}", arpRequest.getSenderProtocolAddress().toString());

		return;
	}


	public void pushPacket(IPacket packet,
						   IOFSwitch sw,
						   OFBufferId bufferId,
						   OFPort inPort,
						   OFPort outPort,
						   FloodlightContext cntx,
						   boolean flush) {
		if (logger.isTraceEnabled()) {
			logger.trace("PacketOut srcSwitch={} inPort={} outPort={}",
					new Object[] {sw, inPort, outPort});
		}

		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();

		// set actions
		List<OFAction> actions = new ArrayList<OFAction>();
		actions.add(sw.getOFFactory().actions().buildOutput().setPort(outPort).setMaxLen(Integer.MAX_VALUE).build());

		pob.setActions(actions);

		// set buffer_id, in_port
		pob.setBufferId(bufferId);
		pob.setInPort(inPort);

		// set data - only if buffer_id == -1
		if (pob.getBufferId() == OFBufferId.NO_BUFFER) {
			if (packet == null) {
				logger.error("BufferId is not set and packet data is null. " +
								"Cannot send packetOut. " +
								"srcSwitch={} inPort={} outPort={}",
						new Object[] {sw, inPort, outPort});
				return;
			}
			byte[] packetData = packet.serialize();
			pob.setData(packetData);
		}

		//counterPacketOut.increment();
		logger.info("Wrote package to switch");
		sw.write(pob.build());
	}






}
