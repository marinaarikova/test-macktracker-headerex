package net.floodlightcontroller.headerextract;

import java.net.SocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.projectfloodlight.openflow.protocol.OFActionType;
import org.projectfloodlight.openflow.protocol.OFCapabilities;
import org.projectfloodlight.openflow.protocol.OFControllerRole;
import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFFlowAdd.Builder;
import org.projectfloodlight.openflow.protocol.OFFlowDelete;
import org.projectfloodlight.openflow.protocol.OFFlowDeleteStrict;
import org.projectfloodlight.openflow.protocol.OFFlowModCommand;
import org.projectfloodlight.openflow.protocol.OFFlowModify;
import org.projectfloodlight.openflow.protocol.OFFlowModifyStrict;
import org.projectfloodlight.openflow.protocol.OFMatch;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFRequest;
import org.projectfloodlight.openflow.protocol.OFStatsReply;
import org.projectfloodlight.openflow.protocol.OFStatsRequest;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActionPopVlan;
import org.projectfloodlight.openflow.protocol.action.OFActionSetField;
import org.projectfloodlight.openflow.protocol.action.OFActions;
import org.projectfloodlight.openflow.protocol.instruction.OFInstruction;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionApplyActions;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.oxm.OFOxms;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv4AddressWithMask;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TableId;
import org.projectfloodlight.openflow.types.TransportPort;
import org.projectfloodlight.openflow.types.U64;
import org.projectfloodlight.openflow.util.HexString;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.util.concurrent.ListenableFuture;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFConnection;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.LogicalOFMessageCategory;
import net.floodlightcontroller.core.PortChangeType;
import net.floodlightcontroller.core.SwitchDescription;
import net.floodlightcontroller.core.internal.OFConnection;
import net.floodlightcontroller.core.internal.TableFeatures;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.BasePacket;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.staticentry.IStaticEntryPusherService;
import net.floodlightcontroller.statistics.IStatisticsService;
import net.floodlightcontroller.util.FlowModUtils;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

public class HeaderExtract implements IFloodlightModule,IOFSwitchListener,IOFSwitch, IOFMessageListener {
	public final int DEFAULT_CACHE_SIZE = 10;
	protected IFloodlightProviderService floodlightProvider;
	private IStaticEntryPusherService flowPusher;
	private IStaticEntryPusherService staticentrypusher;
	private Object switchService;
	private OFFactory myFactory;
	private OFFactory my13Factory;

	private List<OFInstruction> myInstructionList;
	private OFFlowAdd flowAdd;
	private List<OFInstruction> newInstructionList;
	private List<OFAction> myActionList;
	private OFFlowAdd flowAdd13;
	private OFFactory factory;
	private OFFactory myOF13Factory;
	private Logger logger;

	@Override
	public String getName() {
		return "Names";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}

	// This is where we pull fields from the packet-in
	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		BasePacket pkt = (BasePacket) IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		// Instantiate two objects for OFMatch and OFPacketIn
		OFPacketIn pin = (OFPacketIn) msg;
		OFMatch match = new OFMatch();
		match.loadFromPacket(pin.getData(), pin.getInPort());
		// Destination IP Address for each packet-in
		System.out.println("$$$$$-Get the Desitnation IP Address-$$$$$");
		System.out.println(IPv4.fromIPv4Address(match.getNetworkDestination()));
		// Source Mac Address for each packet-in
		System.out.println("$$$$$-Mac Address Destination-$$$$$$");
		Long sourceMACHash = Ethernet.toLong(match.getDataLayerDestination());
		System.out.println(HexString.toHexString(sourceMACHash));
		// Here we print the entire packet-in array which has all matchable
		// fields
		System.out.println("$$$$$-PacketIn ARRAY-$$$$$");
		System.out.println(Arrays.asList(match));

		return Command.CONTINUE;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		l.add(IStaticEntryPusherService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		staticentrypusher = context.getServiceImpl(IStaticEntryPusherService.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}

	@Override
	public void switchAdded(DatapathId switchId) {
		// TODO Auto-generated method stub
		logger.info(": {} seen on switch: {}");
		System.out.println("привет");
//		ArrayList<OFAction> actionList = new ArrayList<OFAction>();
//		OFActions actions = myOF13Factory.actions();
//		OFOxms oxms = myOF13Factory.oxms();
		 
		/* Use OXM to modify data layer dest field. */
//		OFActionSetField setDlDst = actions.buildSetField()
//		    .setField(
//		        oxms.buildEthDst()
//		        .setValue(MacAddress.of("ff:ff:ff:ff:ff:ff"))
//		        .build()
//		    )
//		    .build();
//		actionList.add(setDlDst);
//		 
//		/* Use OXM to modify network layer dest field. */
//		OFActionSetField setNwDst = actions.buildSetField()
//		    .setField(
//		        oxms.buildIpv4Dst()
//		        .setValue(IPv4Address.of("255.255.255.255"))
//		        .build()
//		    )
//		    .build();
//		actionList.add(setNwDst);
//		 
//		/* Popping the VLAN tag is not an OXM but an OFAction. */
//		OFActionPopVlan popVlan = actions.popVlan();
//		actionList.add(popVlan);
//		 
//		/* Output to a port is also an OFAction, not an OXM. */
//		OFActionOutput output = actions.buildOutput()
//		    .setMaxLen(0xFFffFFff)
//		    .setPort(OFPort.of(1))
//		    .build();
//		actionList.add(output);
//					

	}
	
	
	
	private Builder setBufferId(OFBufferId noBuffer) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void switchRemoved(DatapathId switchId) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void switchActivated(DatapathId switchId) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void switchPortChanged(DatapathId switchId, OFPortDesc port, PortChangeType type) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void switchChanged(DatapathId switchId) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void switchDeactivated(DatapathId switchId) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public boolean write(OFMessage m) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Collection<OFMessage> write(Iterable<OFMessage> msgList) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public <R extends OFMessage> ListenableFuture<R> writeRequest(OFRequest<R> request) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public <REPLY extends OFStatsReply> ListenableFuture<List<REPLY>> writeStatsRequest(OFStatsRequest<REPLY> request) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SwitchStatus getStatus() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public long getBuffers() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public void disconnect() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public Set<OFActionType> getActions() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Set<OFCapabilities> getCapabilities() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<TableId> getTables() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SwitchDescription getSwitchDescription() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public SocketAddress getInetAddress() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<OFPortDesc> getEnabledPorts() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<OFPort> getEnabledPortNumbers() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public OFPortDesc getPort(OFPort portNumber) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public OFPortDesc getPort(String portName) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<OFPortDesc> getPorts() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<OFPortDesc> getSortedPorts() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean portEnabled(OFPort portNumber) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean portEnabled(String portName) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isConnected() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Date getConnectedSince() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public DatapathId getId() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Object, Object> getAttributes() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean isActive() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public OFControllerRole getControllerRole() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean hasAttribute(String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Object getAttribute(String name) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean attributeEquals(String name, Object other) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void setAttribute(String name, Object value) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public Object removeAttribute(String name) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public OFFactory getOFFactory() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public ImmutableList<IOFConnection> getConnections() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean write(OFMessage m, LogicalOFMessageCategory category) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Iterable<OFMessage> write(Iterable<OFMessage> msglist, LogicalOFMessageCategory category) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public OFConnection getConnectionByCategory(LogicalOFMessageCategory category) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public <REPLY extends OFStatsReply> ListenableFuture<List<REPLY>> writeStatsRequest(OFStatsRequest<REPLY> request,
			LogicalOFMessageCategory category) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public <R extends OFMessage> ListenableFuture<R> writeRequest(OFRequest<R> request,
			LogicalOFMessageCategory category) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public TableFeatures getTableFeatures(TableId table) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public short getNumTables() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public U64 getLatency() {
		// TODO Auto-generated method stub
		return null;
	}
}