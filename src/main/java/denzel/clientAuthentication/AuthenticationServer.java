package denzel.clientAuthentication;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.handler.codec.LengthFieldBasedFrameDecoder;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslHandshakeCompletionEvent;
import io.netty.incubator.codec.quic.*;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.util.concurrent.TimeUnit;

public class AuthenticationServer {

    public static void main(String[] args) throws CertificateException {
        try {
            System.setProperty("javax.net.debug", "ssl,handshake");

            var keyManager = Util.getKeyManager();
            var trustManager = new TrustManagerWrapper(Util.getTrustManager());

            long size = 100_000_000;
            QuicSslContext quicSslContext = QuicSslContextBuilder
                    .forServer(keyManager, "")
                    .trustManager(trustManager)
                    .clientAuth(ClientAuth.REQUIRE)
                    .applicationProtocols("TLSv1.3")
                    .build();

            NioEventLoopGroup group = new NioEventLoopGroup(10);

            ChannelHandler codec = new QuicServerCodecBuilder().sslContext(quicSslContext)
                    .maxIdleTimeout(100_000, TimeUnit.MILLISECONDS)
                    .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 100_000)
                    .initialMaxData(size)
                    .initialMaxStreamsBidirectional(size)
                    .initialMaxStreamDataBidirectionalLocal(size)
                    .initialMaxStreamDataBidirectionalRemote(size)
                    .activeMigration(true)
                    .tokenHandler(InsecureQuicTokenHandler.INSTANCE)
                    .handler(new ChannelInboundHandlerAdapter() {
                        @Override
                        public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
                            if (evt instanceof SslHandshakeCompletionEvent) {
                                System.out.println("Handshake completed " + evt);
                            }
                        }

                        @Override
                        public boolean isSharable() {
                            return true;
                        }
                    })
                    .streamHandler(new ChannelInitializer<QuicStreamChannel>() {
                        @Override
                        protected void initChannel(QuicStreamChannel ch) {
                            ch.pipeline().addLast(new LengthFieldBasedFrameDecoder(100_000, 0, 4, 0, 4));
                            ch.pipeline().addLast(new ChannelInboundHandlerAdapter() {
                                @Override
                                public void channelRead(ChannelHandlerContext ctx, Object msg) {
                                    var byteBuf = (ByteBuf) msg;
                                    try {
                                        var message = byteBuf.toString(StandardCharsets.US_ASCII);
                                        System.out.println(message);
                                    } catch (Exception e) {
                                        e.printStackTrace();
                                    } finally {
                                        byteBuf.release();
                                    }
                                }
                            });
                        }
                    }).build();

            Bootstrap bs = new Bootstrap();
            var channel = bs.group(group)
                    .channel(NioDatagramChannel.class)
                    .handler(codec)
                    .bind(new InetSocketAddress(9999))
                    .sync().channel();
            System.out.println("Server ready");
            channel.closeFuture().sync();
            group.shutdownGracefully();
        }catch (Exception e) {
            e.printStackTrace();
        }

    }

}