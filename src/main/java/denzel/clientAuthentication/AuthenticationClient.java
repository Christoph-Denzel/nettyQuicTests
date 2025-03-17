package denzel.clientAuthentication;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.handler.codec.LengthFieldPrepender;
import io.netty.handler.ssl.SslHandshakeCompletionEvent;
import io.netty.incubator.codec.quic.QuicChannel;
import io.netty.incubator.codec.quic.QuicClientCodecBuilder;
import io.netty.incubator.codec.quic.QuicSslContextBuilder;
import io.netty.incubator.codec.quic.QuicStreamType;
import io.netty.util.CharsetUtil;

import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;

import static io.netty.buffer.Unpooled.copiedBuffer;

public class AuthenticationClient {


    public static void main(String[] args) {
        long size = 100_000_000;
        try {
            var keyManager = Util.getKeyManager();
            var trustManager = new TrustManagerWrapper(Util.getTrustManager());

            var quicSslContext = QuicSslContextBuilder.forClient()
                    .applicationProtocols("TLSv1.3")
                    .trustManager(trustManager)
                    .keyManager(keyManager, "")
                    .build();

            var codec = new QuicClientCodecBuilder()
                    .sslContext(quicSslContext)
                    .maxIdleTimeout(50_000, TimeUnit.MILLISECONDS)
                    .initialMaxData(size)
                    .initialMaxStreamsBidirectional(size)
                    .initialMaxStreamDataUnidirectional(size)
                    .initialMaxStreamDataBidirectionalRemote(size)
                    .build();

            var eventLoopGroup = new NioEventLoopGroup(1);
            var bs = new Bootstrap();
            var channel = bs.group(eventLoopGroup)
                    .channel(NioDatagramChannel.class)
                    .handler(codec)
                    .bind(0)
                    .sync().channel();

            var quicChannel = QuicChannel.newBootstrap(channel)
                    .handler(new ChannelInboundHandlerAdapter() {
                        @Override
                        public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
                            if (evt instanceof SslHandshakeCompletionEvent) {
                                System.out.println("Handshake completed " + evt);
                            }
                        }
                    })
                    .remoteAddress(new InetSocketAddress("127.0.0.1", 9999))
                    .connect().sync().get();

            var streamChannel = quicChannel.createStream(QuicStreamType.BIDIRECTIONAL,
                    new ChannelInboundHandlerAdapter() {
                    }).sync().get();

            streamChannel.pipeline().addLast(new LengthFieldPrepender(4, false));
            streamChannel.writeAndFlush(copiedBuffer("Hello World!", CharsetUtil.UTF_8));

            streamChannel.closeFuture().sync();
            quicChannel.closeFuture().sync();
            channel.closeFuture().sync();
            eventLoopGroup.shutdownGracefully();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
