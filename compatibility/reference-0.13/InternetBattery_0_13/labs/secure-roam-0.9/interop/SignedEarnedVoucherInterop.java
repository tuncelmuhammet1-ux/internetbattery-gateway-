import com.internetbattery.capacity.*;
import com.internetbattery.broker.*;
import java.nio.file.*;
import java.security.*;
import java.time.Clock;
import java.util.*;

public class SignedEarnedVoucherInterop {
  public static void main(String[] args) throws Exception {
    if(args.length!=1)throw new IllegalArgumentException("temporary workdir required");
    byte[] gatewayKey=new byte[32],journalKey=new byte[32],holderKey=new byte[32],consumerKey=new byte[32];
    SecureRandom rnd=new SecureRandom();
    rnd.nextBytes(gatewayKey);rnd.nextBytes(journalKey);rnd.nextBytes(holderKey);rnd.nextBytes(consumerKey);
    Path work=Paths.get(args[0]);
    Files.createDirectories(work);
    CapacityLedger ledger=new CapacityLedger(
      work.resolve("capacity-ledger-jvm.bin"),journalKey,
      List.of(new TrustedGateway("gateway-a","provider-1",gatewayKey)),
      Clock.systemUTC()
    );
    // Demo preallocation is *not* earned mobile data. The broker's reciprocal transfer is tested separately.
    ledger.seedTestQuota("consumer-1",50000L);
    KeyPair issuer=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    MutualReceiptBroker broker=new MutualReceiptBroker(
      ledger,issuer.getPrivate(),
      Map.of("provider-1",holderKey,"consumer-1",consumerKey),
      Set.of("gateway-b"));
    long now=System.currentTimeMillis();
    UsageReceipt receipt=new GatewayReceiptSigner("gateway-a",gatewayKey)
      .sign("real-metering-test","consumer-1",4000,27000,now);
    String approval=MutualReceiptBroker.Companion.signConsumerApproval(consumerKey,receipt);
    if(!broker.settle(receipt,approval))throw new IllegalStateException("measured mutual receipt refused");
    if(broker.balance("provider-1")!=31000L)throw new IllegalStateException("earned experimental balance != 31000");
    String issueAuth=MutualReceiptBroker.Companion.signIssueRequest(
      holderKey,"provider-1","cross-lang-v13","gateway-b",20000L,30L);
    PortableVoucher voucher=broker.issueVoucher("provider-1","cross-lang-v13","gateway-b",
      20000L,issueAuth,30L);
    if(voucher==null)throw new IllegalStateException("voucher issue failed");
    if(broker.balance("provider-1")!=11000L)throw new IllegalStateException("reserve not debited");
    String wire=VoucherCredential.INSTANCE.encode(voucher);
    if(wire.length()>255)throw new IllegalStateException("IB1 too large for SOCKS5");
    System.out.println("PUBLIC_DER_B64="+Base64.getEncoder().encodeToString(issuer.getPublic().getEncoded()));
    System.out.println("IB1="+wire);
    System.out.println("EARNED_CREDIT=31000");
    System.out.println("RESERVED_BYTES=20000");
    System.out.println("BALANCE_AFTER_ISSUE=11000");
  }
}
