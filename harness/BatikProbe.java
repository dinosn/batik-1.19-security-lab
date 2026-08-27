// Shared transcoder harness for the Batik 1.19 security lab.
// Renders an SVG through PNGTranscoder with a caller-set document URI, using the DEFAULT
// UserAgentAdapter (i.e. DefaultExternalResourceSecurity / DefaultScriptSecurity — same-host).
// Used by F-1, F-2, F-6, F-9. Prints TRANSCODE_OK or the full exception cause chain.
import org.apache.batik.transcoder.*;
import org.apache.batik.transcoder.image.PNGTranscoder;
import java.io.*;

public class BatikProbe {
    // args: <svgFile> <docURI|-> [outPng]
    public static void main(String[] a) throws Exception {
        String svg = a[0];
        String docURI = (a.length > 1 && !a[1].equals("-")) ? a[1] : null;
        String out = (a.length > 2) ? a[2] : "/tmp/batik-lab/probe.out.png";
        PNGTranscoder t = new PNGTranscoder();
        TranscoderInput in = new TranscoderInput(new FileInputStream(svg));
        if (docURI != null) in.setURI(docURI);
        TranscoderOutput o = new TranscoderOutput(new FileOutputStream(out));
        try {
            t.transcode(in, o);
            System.out.println("TRANSCODE_OK");
        } catch (Throwable e) {
            Throwable c = e;
            while (c != null) {
                System.out.println("  CAUSE: " + c.getClass().getName() + ": " + c.getMessage());
                c = c.getCause();
            }
        }
    }
}
