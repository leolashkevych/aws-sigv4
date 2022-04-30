package burp;

import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.swing.*;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.StringReader;

import static burp.SigProfile.DEFAULT_STATIC_PRIORITY;
import static burp.SigProfile.getTempProfileName;

public class AddTempCredsActionListener implements ActionListener {

    enum CONTENT_TYPE{
        JSON,
        XML
    }
    private static final BurpExtender burp = BurpExtender.getBurp();
    private final String responseBody;
    private final CONTENT_TYPE contentType;

    public AddTempCredsActionListener(String responseBody, CONTENT_TYPE contentType){
        super();
        this.responseBody = responseBody;
        this.contentType = contentType;
    }

    private SigCredential extractCredentials(String responseBody, CONTENT_TYPE contentType) throws ParserConfigurationException, IOException, SAXException {
        if(contentType == CONTENT_TYPE.JSON){
            try {
                JSONTokener tokener = new JSONTokener(responseBody);
                JSONObject jsonObject = new JSONObject(tokener);
                JSONObject credObject = jsonObject.getJSONObject("Credentials");
                String accessKeyId = credObject.getString("AccessKeyId");
                String secretKey = credObject.getString("SecretKey");
                String sessionToken = credObject.getString("SessionToken");
                return new SigTemporaryCredential(accessKeyId, secretKey, sessionToken, 0);
            } catch (JSONException ex) {
                JOptionPane.showMessageDialog(null,
                        "Unable to load assumed role credentials. Check the Error output for details.",
                        "Error",
                        JOptionPane.ERROR_MESSAGE);
                burp.logger.error(String.format("Unable to load assumed role credentials: %s", ex.getMessage()));
            }
        } else if (contentType == CONTENT_TYPE.XML) {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(responseBody)));
            String accessKeyId = doc.getElementsByTagName("AccessKeyId").item(0).getTextContent();
            String secretKey = doc.getElementsByTagName("SecretAccessKey").item(0).getTextContent();
            String sessionToken = doc.getElementsByTagName("SessionToken").item(0).getTextContent();
            return new SigTemporaryCredential(accessKeyId, secretKey, sessionToken, 0);
        }
        return null;
    }

    private String getProfileName() throws NullPointerException{
        return (String) JOptionPane.showInputDialog(
                null,
                "Profile name:",
                "Add Profile",
                JOptionPane.PLAIN_MESSAGE,
                null,
                null,
                getTempProfileName());
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        try {
            SigCredential staticCredential = extractCredentials(this.responseBody, this.contentType);
            assert staticCredential != null;
            SigProfile tempProfile = new SigProfile.Builder(getProfileName())
                    .withAccessKeyId(staticCredential.getAccessKeyId())
                    .withCredentialProvider(new SigStaticCredentialProvider(staticCredential), DEFAULT_STATIC_PRIORITY)
                    .build();

            burp.addProfile(tempProfile);
            JOptionPane.showMessageDialog(null,
                    "Temporary credentials are added: " + tempProfile.getName(),
                    "Profile Added",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (IllegalArgumentException ex){
            JOptionPane.showMessageDialog(null,
                    "Error: " + ex.getMessage(),
                    "Conflict Exception",
                    JOptionPane.ERROR_MESSAGE);
        } catch (NullPointerException ex){
            burp.logger.error("Assumed role not saved: no profile name provided.");
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(null,
                    "Unable to load assumed role credentials. Check the Error output for details.",
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
            burp.logger.error(String.format("Unable to load assumed role credentials: %s", ex.getMessage()));
        }
    }
}
