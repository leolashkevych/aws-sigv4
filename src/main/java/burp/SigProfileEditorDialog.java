package burp;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionListener;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

public class SigProfileEditorDialog extends JDialog
{
    static final Color disabledColor = new Color(161, 161, 161);

    private static final BurpExtender burp = BurpExtender.getBurp();

    protected JTextField nameTextField;
    protected JTextField profileKeyIdTextField;
    protected JTextFieldHint regionTextField;
    protected JTextFieldHint serviceTextField;

    protected JButton okButton;
    protected JPanel providerPanel;

    // static creds fields
    private JRadioButton staticProviderRadioButton;
    private JTextField accessKeyIdTextField;
    protected JTextField secretKeyTextField;
    protected JTextField sessionTokenTextField;

    // Assume role fields
    private JRadioButton assumeRoleProviderRadioButton;
    private JTextField roleArnTextField;
    private JTextField sessionNameTextField;
    private JTextField externalIdTextField;

    private JComboBox<String> optionsComboBox;

    private JTextArea assumeRolePolicyTextArea;

    private JScrollPane assumeRolePolicyScrollPane;

    // Http provider
    private JRadioButton httpProviderRadioButton;

    private JRadioButton commandProviderRadioButton;

    private JTextField httpProviderUrlField;

    private JTextField commandProviderField;


    private MultilineLabel statusLabel;
    private String newProfileName = null;

    // allow creator of dialog to get the profile that was created
    public String getNewProfileName() { return newProfileName; }

    public String getDefaultAssumeRolePolicy(){
        return "{\n" +
                "    \"Version\": \"2012-10-17\",\n" +
                "    \"Statement\": [\n" +
                "        {\n" +
                "            \"Effect\": \"Allow\",\n" +
                "            \"Action\": \"*\",\n" +
                "            \"Resource\": \"*\"\n" +
                "        }\n" +
                "    ]\n" +
                "}";
    }
    private String policyDenyAll = "{\n" +
            "    \"Version\": \"2012-10-17\",\n" +
            "    \"Statement\": [\n" +
            "        {\n" +
            "            \"Effect\": \"Deny\",\n" +
            "            \"Action\": \"*\",\n" +
            "            \"Resource\": \"*\"\n" +
            "        }\n" +
            "    ]\n" +
            "}";
    private String policyExplicitAllow = "{\n" +
            "    \"Version\": \"2012-10-17\",\n" +
            "    \"Statement\": [\n" +
            "        {\n" +
            "            \"Effect\": \"Allow\",\n" +
            "            \"Action\": \"service:operation\",\n" +
            "            \"Resource\": \"*\"\n" +
            "        }\n" +
            "    ]\n" +
            "}";

    private String policyDenyPassRole = "{\n" +
            "    \"Version\": \"2012-10-17\",\n" +
            "    \"Statement\": [\n" +
            "        {\n" +
            "            \"Effect\": \"Allow\",\n" +
            "            \"Action\": \"*\",\n" +
            "            \"Resource\": \"*\"\n" +
            "        },\n" +
            "        {\n" +
            "            \"Effect\": \"Deny\",\n" +
            "            \"Action\": \"iam:PassRole\",\n" +
            "            \"Resource\": \"*\"\n" +
            "        }\n" +
            "    ]\n" +
            "}";

    private String policyExplicitDeny = "{\n" +
            "    \"Version\": \"2012-10-17\",\n" +
            "    \"Statement\": [\n" +
            "        {\n" +
            "            \"Effect\": \"Allow\",\n" +
            "            \"Action\": \"*\",\n" +
            "            \"Resource\": \"*\"\n" +
            "        },\n" +
            "        {\n" +
            "            \"Effect\": \"Deny\",\n" +
            "            \"Action\": \"service:operation\",\n" +
            "            \"Resource\": \"*\"\n" +
            "        }\n" +
            "    ]\n" +
            "}";

    private String policyExplicitAllowForResource = "{\n" +
            "    \"Version\": \"2012-10-17\",\n" +
            "    \"Statement\": [\n" +
            "        {\n" +
            "            \"Effect\": \"Allow\",\n" +
            "            \"Action\": \"service:operation\",\n" +
            "            \"Resource\": \"arn:partition:service:region:account-id:resource-id\"\n" +
            "        }\n" +
            "    ]\n" +
            "}";
    private String policyExplicitDenyForResource = "{\n" +
            "    \"Version\": \"2012-10-17\",\n" +
            "    \"Statement\": [\n" +
            "        {\n" +
            "            \"Effect\": \"Allow\",\n" +
            "            \"Action\": \"*\",\n" +
            "            \"Resource\": \"*\"\n" +
            "        },\n" +
            "        {\n" +
            "            \"Effect\": \"Deny\",\n" +
            "            \"Action\": \"service:operation\",\n" +
            "            \"Resource\": \"arn:partition:service:region:account-id:resource-id\"\n" +
            "        }\n" +
            "    ]\n" +
            "}";

    private String policyExplicitAllowForResourceAccount = "{\n" +
            "    \"Version\": \"2012-10-17\",\n" +
            "    \"Statement\": [\n" +
            "        {\n" +
            "            \"Effect\": \"Allow\",\n" +
            "            \"Action\": \"*\",\n" +
            "            \"Resource\": \"arn:partition:service:region:account-id:resource-id\",\n" +
            "            \"Condition\": {\n" +
            "                \"StringEquals\": {\n" +
            "                    \"aws:ResourceAccount\": \"123456789012\"\n" +
            "                }\n" +
            "            }\n" +
            "        }\n" +
            "    ]\n" +
            "}";

    private String policyExplicitAllowForIpAddress = "{\n" +
            "    \"Version\": \"2012-10-17\",\n" +
            "    \"Statement\": [\n" +
            "        {\n" +
            "            \"Effect\": \"Allow\",\n" +
            "            \"Action\": \"*\",\n" +
            "            \"Resource\": \"*\",\n" +
            "            \"Condition\": {\n" +
            "                \"IpAddress\": {\n" +
            "                    \"aws:SourceIp\": \"127.0.0.1\"\n" +
            "                }\n" +
            "            }\n" +
            "        }\n" +
            "    ]\n" +
            "}";

    private String policyExplicitDenyForIpAddress = "{\n" +
            "    \"Version\": \"2012-10-17\",\n" +
            "    \"Statement\": [\n" +
            "        {\n" +
            "            \"Effect\": \"Allow\",\n" +
            "            \"Action\": \"*\",\n" +
            "            \"Resource\": \"*\"\n" +
            "        },\n" +
            "        {\n" +
            "            \"Effect\": \"Deny\",\n" +
            "            \"Action\": \"*\",\n" +
            "            \"Resource\": \"*\",\n" +
            "            \"Condition\": {\n" +
            "                \"IpAddress\": {\n" +
            "                    \"aws:SourceIp\": \"127.0.0.1\"\n" +
            "                }\n" +
            "            }\n" +
            "        }\n" +
            "    ]\n" +
            "}";


    private static GridBagConstraints newConstraint(int gridx, int gridy, int gridwidth, int gridheight)
    {
        GridBagConstraints c = new GridBagConstraints();
        c.gridy = gridy;
        c.gridx = gridx;
        c.gridwidth = gridwidth;
        c.gridheight = gridheight;
        return c;
    }

    private static GridBagConstraints newConstraint(int gridx, int gridy, int anchor)
    {
        GridBagConstraints c = newConstraint(gridx, gridy, 1, 1);
        c.anchor = anchor;
        return c;
    }

    private static GridBagConstraints newConstraint(int gridx, int gridy)
    {
        return newConstraint(gridx, gridy, 1, 1);
    }

    /*
    return a dialog with a form for editing profiles. optional profile param can be used to populate the form.
    set profile to null for a create form.
     */
    public SigProfileEditorDialog(Frame owner, String title, boolean modal, SigProfile profile)
    {
        super(owner, title, modal);
        setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);

        JPanel outerPanel = new JPanel(new GridBagLayout());
        final int TEXT_FIELD_WIDTH = 40;
        int outerPanelY = 0;
        int providerPanelY = 0;

        // panel for required fields
        JPanel basicPanel = new JPanel(new GridBagLayout());
        basicPanel.setBorder(new TitledBorder("Profile"));
        basicPanel.add(new JLabel("Name"), newConstraint(0, 0, GridBagConstraints.LINE_START));
        this.nameTextField = new JTextFieldHint("", TEXT_FIELD_WIDTH, "Required");
        basicPanel.add(nameTextField, newConstraint(1, 0));
        basicPanel.add(new JLabel("KeyId"), newConstraint(0, 1, GridBagConstraints.LINE_START));
        this.profileKeyIdTextField = new JTextFieldHint("", TEXT_FIELD_WIDTH, "Optional - Match with AccessKeyId in incoming requests");
        this.profileKeyIdTextField.setToolTipText("Look for this AccessKeyId in a request to automatically select this profile");
        basicPanel.add(profileKeyIdTextField, newConstraint(1, 1));
        basicPanel.add(new JLabel("Region"), newConstraint(0, 2, GridBagConstraints.LINE_START));
        // for add profile dialog, fill default region
        this.regionTextField = new JTextFieldHint(profile == null ? SigProfile.getDefaultRegion() : "", TEXT_FIELD_WIDTH, "Optional");
        basicPanel.add(regionTextField, newConstraint(1, 2));
        basicPanel.add(new JLabel("Service"), newConstraint(0, 3, GridBagConstraints.LINE_START));
        this.serviceTextField = new JTextFieldHint("", TEXT_FIELD_WIDTH, "Optional");
        basicPanel.add(serviceTextField, newConstraint(1, 3));
        outerPanel.add(basicPanel, newConstraint(0, outerPanelY++, GridBagConstraints.LINE_START));

        providerPanel = new JPanel(new GridBagLayout());

        // RadioButton panel for selecting credential provider
        staticProviderRadioButton = new JRadioButton("Static credentials");
        staticProviderRadioButton.setSelected(true); //default
        assumeRoleProviderRadioButton = new JRadioButton("AssumeRole");
        httpProviderRadioButton = new JRadioButton("HttpGet");
        commandProviderRadioButton = new JRadioButton("CLI Command");
        ButtonGroup providerButtonGroup = new ButtonGroup();
        providerButtonGroup.add(staticProviderRadioButton);
        providerButtonGroup.add(assumeRoleProviderRadioButton);
        providerButtonGroup.add(httpProviderRadioButton);
        providerButtonGroup.add(commandProviderRadioButton);
        JPanel providerButtonPanel = new JPanel(new FlowLayout());
        providerButtonPanel.add(staticProviderRadioButton);
        providerButtonPanel.add(assumeRoleProviderRadioButton);
        providerButtonPanel.add(httpProviderRadioButton);
        providerButtonPanel.add(commandProviderRadioButton);
        providerPanel.add(providerButtonPanel, newConstraint(0, providerPanelY++, GridBagConstraints.LINE_START));

        // panel for static credentials
        JPanel staticCredentialsPanel = new JPanel(new GridBagLayout());
        staticCredentialsPanel.setBorder(new TitledBorder("Credentials"));
        staticCredentialsPanel.add(new JLabel("AccessKeyId"), newConstraint(0, 0, GridBagConstraints.LINE_START));
        this.accessKeyIdTextField = new JTextFieldHint("", TEXT_FIELD_WIDTH-3, "Required");
        staticCredentialsPanel.add(accessKeyIdTextField, newConstraint(1, 0));
        staticCredentialsPanel.add(new JLabel("SecretKey"), newConstraint(0, 1, GridBagConstraints.LINE_START));
        this.secretKeyTextField = new JTextFieldHint("", TEXT_FIELD_WIDTH-3, "Required");
        staticCredentialsPanel.add(secretKeyTextField, newConstraint(1, 1));
        staticCredentialsPanel.add(new JLabel("SessionToken"), newConstraint(0, 2, GridBagConstraints.LINE_START));
        this.sessionTokenTextField = new JTextFieldHint("", TEXT_FIELD_WIDTH-3, "Optional");
        staticCredentialsPanel.add(sessionTokenTextField, newConstraint(1, 2));
        providerPanel.add(staticCredentialsPanel, newConstraint(0, providerPanelY++, GridBagConstraints.LINE_START));

        // assume role policy templates

        Map<String, String> optionTextMap = new HashMap<>();
        optionTextMap.put("Allow All", getDefaultAssumeRolePolicy());
        optionTextMap.put("Deny All", policyDenyAll);
        optionTextMap.put("Explicit Allow", policyExplicitAllow);
        optionTextMap.put("Explicit Deny", policyExplicitDeny);
        optionTextMap.put("Deny PassRole", policyDenyPassRole);
        optionTextMap.put("Explicit Allow for Resource", policyExplicitAllowForResource);
        optionTextMap.put("Explicit Deny for Resource", policyExplicitDenyForResource);
        optionTextMap.put("Explicit Allow for Resource Account", policyExplicitAllowForResourceAccount);
        optionTextMap.put("IP Address Allow", policyExplicitAllowForIpAddress);
        optionTextMap.put("IP Address Deny", policyExplicitDenyForIpAddress);

        // panel for assume role fields
        JPanel rolePanel = new JPanel(new GridBagLayout());
        rolePanel.setBorder(new TitledBorder("Role"));
        rolePanel.add(new JLabel("RoleArn"), newConstraint(0, 0, GridBagConstraints.LINE_START));
        this.roleArnTextField = new JTextFieldHint("", TEXT_FIELD_WIDTH-3, "Required");
        rolePanel.add(this.roleArnTextField, newConstraint(1, 0));
        rolePanel.add(new JLabel("SessionName"), newConstraint(0, 1, GridBagConstraints.LINE_START));
        this.sessionNameTextField = new JTextFieldHint("", TEXT_FIELD_WIDTH-3, "Optional");
        rolePanel.add(this.sessionNameTextField, newConstraint(1, 1));
        rolePanel.add(new JLabel("ExternalId"), newConstraint(0, 2, GridBagConstraints.LINE_START));
        this.externalIdTextField = new JTextFieldHint("", TEXT_FIELD_WIDTH-3, "Optional");
        rolePanel.add(this.externalIdTextField, newConstraint(1, 2));
        this.optionsComboBox = new JComboBox<>(optionTextMap.keySet().toArray(new String[0]));
        rolePanel.add(optionsComboBox, newConstraint(1, 3));
        rolePanel.add(new JLabel("Policy Template"), newConstraint(0, 3, GridBagConstraints.LINE_START));
        this.optionsComboBox.setSelectedItem(null);
        rolePanel.add(new JLabel("Policy"), newConstraint(0, 4, GridBagConstraints.LINE_START));
        this.assumeRolePolicyTextArea = new JTextArea(10, TEXT_FIELD_WIDTH - 4);
        this.assumeRolePolicyTextArea.setLineWrap(true);
        this.assumeRolePolicyTextArea.setText(getDefaultAssumeRolePolicy());
        this.assumeRolePolicyScrollPane = new JScrollPane(this.assumeRolePolicyTextArea,
                JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
                JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        rolePanel.add(this.assumeRolePolicyScrollPane, newConstraint(1, 4));
        providerPanel.add(rolePanel, newConstraint(0, providerPanelY++, GridBagConstraints.LINE_START));


        // Add an ActionListener to the JComboBox
        this.optionsComboBox.addActionListener(e -> {
            // Get the selected option
            String selectedOption = (String) this.optionsComboBox.getSelectedItem();
            // Get the predefined text for the selected option
            String optionText = optionTextMap.get(selectedOption);
            // Update the assumeRolePolicyTextArea with the predefined text
            this.assumeRolePolicyTextArea.setText(optionText);
        });

        // panel for http provided creds
        JPanel httpPanel = new JPanel(new GridBagLayout());
        httpPanel.setBorder(new TitledBorder("Http Credentials"));
        httpPanel.add(new JLabel("GET URL "), newConstraint(0, 0, GridBagConstraints.LINE_START));
        this.httpProviderUrlField = new JTextFieldHint("", TEXT_FIELD_WIDTH-2, "Required");
        httpPanel.add(this.httpProviderUrlField, newConstraint(1, 0));
        providerPanel.add(httpPanel, newConstraint(0, providerPanelY++, GridBagConstraints.LINE_START));

        // panel for CLI Command
        JPanel commandPanel = new JPanel(new GridBagLayout());
        commandPanel.setBorder(new TitledBorder("CLI Command"));
        commandPanel.add(new JLabel("Command "), newConstraint(0, 0, GridBagConstraints.LINE_START));
        this.commandProviderField = new JTextFieldHint("", TEXT_FIELD_WIDTH-2, "Required");
        commandPanel.add(this.commandProviderField, newConstraint(1, 0));
        providerPanel.add(commandPanel, newConstraint(0, providerPanelY++, GridBagConstraints.LINE_START));

        outerPanel.add(providerPanel, newConstraint(0, outerPanelY++, GridBagConstraints.LINE_START));
        statusLabel = new MultilineLabel("Ok to submit");
        Font defaultFont = statusLabel.getFont();
        statusLabel.setFont(new Font(defaultFont.getFamily(), Font.ITALIC, defaultFont.getSize()));
        statusLabel.setForeground(BurpExtender.textOrange);
        okButton = new JButton("Ok");
        JButton cancelButton = new JButton("Cancel");

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(okButton);
        buttonPanel.add(cancelButton);
        outerPanel.add(statusLabel, newConstraint(0, outerPanelY++, 2, 1));
        outerPanel.add(buttonPanel, newConstraint(0, outerPanelY++, 2, 1));

        ActionListener providerButtonActionListener = actionEvent -> {
            staticCredentialsPanel.setVisible(staticProviderRadioButton.isSelected());
            rolePanel.setVisible(assumeRoleProviderRadioButton.isSelected());
            httpPanel.setVisible(httpProviderRadioButton.isSelected());
            commandPanel.setVisible(commandProviderRadioButton.isSelected());
            if (actionEvent.getSource().equals(assumeRoleProviderRadioButton)) {
                staticCredentialsPanel.setVisible(true);
            }
            pack();
        };
        this.staticProviderRadioButton.addActionListener(providerButtonActionListener);
        this.assumeRoleProviderRadioButton.addActionListener(providerButtonActionListener);
        this.httpProviderRadioButton.addActionListener(providerButtonActionListener);
        this.commandProviderRadioButton.addActionListener(providerButtonActionListener);

        cancelButton.addActionListener(actionEvent -> {
            setVisible(false);
            dispose();
        });
        okButton.addActionListener(actionEvent -> {
            SigAssumeRoleCredentialProvider assumeRole = null;
            final String accessKeyId = accessKeyIdTextField.getText();
            final String secretKey = secretKeyTextField.getText();
            final String sessionToken = sessionTokenTextField.getText();

            try {
                if (profile != null && assumeRoleProviderRadioButton.isSelected()) {
                    // edit dialog
                    SigCredential credential = new SigStaticCredential(accessKeyId, secretKey);
                    if (!sessionToken.equals(""))
                        credential = new SigTemporaryCredential(accessKeyId, secretKey, sessionToken, Instant.now().getEpochSecond() + 900);
                    if (profile.getAssumeRole() != null) {
                        assumeRole = new SigAssumeRoleCredentialProvider.Builder(profile.getAssumeRole())
                                .withRoleArn(roleArnTextField.getText())
                                .withCredential(credential)
                                .tryExternalId(externalIdTextField.getText())
                                .tryRoleSessionName(sessionNameTextField.getText())
                                .tryPolicy(assumeRolePolicyTextArea.getText())
                                .build();
                    }
                    else {
                        assumeRole = new SigAssumeRoleCredentialProvider.Builder(roleArnTextField.getText(), credential)
                                .tryExternalId(externalIdTextField.getText())
                                .tryRoleSessionName(sessionNameTextField.getText())
                                .tryPolicy(assumeRolePolicyTextArea.getText())
                                .build();
                    }
                }

                SigProfile.Builder newProfileBuilder = new SigProfile.Builder(nameTextField.getText())
                        .withRegion(regionTextField.getText())
                        .withService(serviceTextField.getText());
                if (!profileKeyIdTextField.getText().equals(""))
                    newProfileBuilder.withAccessKeyId(profileKeyIdTextField.getText());

                if (!httpProviderUrlField.getText().equals("")) {
                    newProfileBuilder.withCredentialProvider(new SigHttpCredentialProvider(httpProviderUrlField.getText()),
                            httpProviderRadioButton.isSelected() ? SigProfile.DEFAULT_HTTP_PRIORITY : SigProfile.DISABLED_PRIORITY);
                }

                if (!commandProviderField.getText().equals("")) {
                    newProfileBuilder.withCredentialProvider(new SigCommandCredentialProvider(commandProviderField.getText()),
                            commandProviderRadioButton.isSelected() ? SigProfile.DEFAULT_COMMAND_PRIORITY : SigProfile.DISABLED_PRIORITY);
                }

                if (assumeRole != null)
                    newProfileBuilder.withCredentialProvider(assumeRole, assumeRoleProviderRadioButton.isSelected() ? SigProfile.DEFAULT_ASSUMEROLE_PRIORITY : SigProfile.DISABLED_PRIORITY);

                // if any cred fields are specified, attempt to use them.
                if (!accessKeyId.equals("") || !secretKey.equals("") || !sessionToken.equals("")) {
                    SigCredential credential = new SigStaticCredential(accessKeyIdTextField.getText(), secretKeyTextField.getText());
                    if (!sessionToken.equals(""))
                        credential = new SigTemporaryCredential(accessKeyId, secretKey, sessionToken, Instant.now().getEpochSecond() + 900);
                    newProfileBuilder.withCredentialProvider(new SigStaticCredentialProvider(credential), SigProfile.DEFAULT_STATIC_PRIORITY);
                }

                final SigProfile newProfile = newProfileBuilder.build();
                if (newProfile.getCredentialProviderCount() <= 0) {
                    throw new IllegalArgumentException("Must provide at least 1 authentication method");
                }
                burp.updateProfile(profile, newProfile);
                newProfileName = newProfile.getName();
                setVisible(false);
                dispose();
            } catch (IllegalArgumentException | IOException | InterruptedException exc) {
                setStatusLabel("Invalid settings: " + exc.getMessage());
            }
        });

        // populate fields with existing profile for an "edit" dialog.
        staticCredentialsPanel.setVisible(staticProviderRadioButton.isSelected());
        httpPanel.setVisible(httpProviderRadioButton.isSelected());
        rolePanel.setVisible(assumeRoleProviderRadioButton.isSelected());
        commandPanel.setVisible(commandProviderRadioButton.isSelected());
        applyProfile(profile);

        add(outerPanel);
        pack();
        // setting to burp.getUiComponent() is not sufficient for dialogs popped outside the SigV4 tab.
        setLocationRelativeTo(SwingUtilities.getWindowAncestor(burp.getUiComponent()));
    }

    protected void setStatusLabel(final String message)
    {
        statusLabel.setText(message);
        pack();
    }

    protected void applyProfile(final SigProfile profile)
    {
        if (profile != null) {
            nameTextField.setText(profile.getName());
            if (profile.getAccessKeyId() != null) {
                profileKeyIdTextField.setText(profile.getAccessKeyId());
            }
            regionTextField.setText(profile.getRegion());
            serviceTextField.setText(profile.getService());
            if (profile.getStaticCredentialProvider() != null) {
                SigCredential credential = profile.getStaticCredentialProvider().getCredential();
                accessKeyIdTextField.setText(credential.getAccessKeyId());
                secretKeyTextField.setText(credential.getSecretKey());
                if (credential.isTemporary()) {
                    sessionTokenTextField.setText(((SigTemporaryCredential)credential).getSessionToken());
                }
                if (profile.getStaticCredentialProviderPriority() >= 0) {
                    staticProviderRadioButton.doClick();
                }
            }
            if (profile.getAssumeRole() != null) {
                roleArnTextField.setText(profile.getAssumeRole().getRoleArn());
                sessionNameTextField.setText(profile.getAssumeRole().getSessionName());
                externalIdTextField.setText(profile.getAssumeRole().getExternalId());
                assumeRolePolicyTextArea.setText(profile.getAssumeRole().getAssumeRolePolicy());
                // initialize static creds as well
                accessKeyIdTextField.setText(profile.getAssumeRole().getStaticCredential().getAccessKeyId());
                secretKeyTextField.setText(profile.getAssumeRole().getStaticCredential().getSecretKey());
                if (profile.getAssumeRole().getStaticCredential().isTemporary()) {
                    sessionTokenTextField.setText(((SigTemporaryCredential)profile.getAssumeRole().getStaticCredential()).getSessionToken());
                }
                if (profile.getAssumeRolePriority() >= 0) {
                    assumeRoleProviderRadioButton.doClick();
                }
            }
            if (profile.getHttpCredentialProvider() != null) {
                httpProviderUrlField.setText(profile.getHttpCredentialProvider().getUrl().toString());
                if (profile.getHttpCredentialProviderPriority() >= 0) {
                    httpProviderRadioButton.doClick();
                }
            }
            if (profile.getCommandCredentialProvider() != null) {
                commandProviderField.setText(profile.getCommandCredentialProvider().getCommand());
                if (profile.getCommandCredentialProviderPriority() >= 0) {
                    commandProviderRadioButton.doClick();
                }
            }
        }
    }
}


/*
This class implements a JTextField with "Optional" hint text when no user input is present.
 */
class JTextFieldHint extends JTextField implements FocusListener
{
    private Font defaultFont;
    private Color defaultForegroundColor;
    final private Color hintForegroundColor = SigProfileEditorDialog.disabledColor;;
    private String hintText;

    public JTextFieldHint(String content, int width, String hintText) {
        // set text below to prevent NullPointerException
        super(width);
        this.hintText = hintText;
        init();
        setText(content);
    }

    void init() {
        defaultFont = getFont();
        addFocusListener(this);
        defaultForegroundColor = getForeground();
        if (super.getText().equals("")) {
            displayHintText();
        }
    }

    @Override
    public String getText() {
        // make sure we don't return "Optional" when these fields are saved
        if (getFont().isItalic()) {
            return "";
        }
        return super.getText();
    }

    @Override
    public void setText(final String text) {
        if (!text.equals("")) {
            setUserText(text);
        }
        else {
            displayHintText();
        }
    }

    protected void setHintText(final String text) {
        this.hintText = text;
        if (getFont().isItalic()) {
            displayHintText();
        }
    }

    protected void displayHintText() {
        setFont(new Font(defaultFont.getFamily(), Font.ITALIC, defaultFont.getSize()));
        setForeground(hintForegroundColor);
        super.setText(hintText);
    }

    private void setUserText(final String text) {
        setFont(defaultFont);
        setForeground(defaultForegroundColor);
        super.setText(text);
    }

    @Override
    public void focusGained(FocusEvent focusEvent) {
        if (getFont().isItalic()) {
            setUserText("");
        }
    }

    @Override
    public void focusLost(FocusEvent focusEvent) {
        if (super.getText().equals("")) {
            displayHintText();
        }
    }
}

