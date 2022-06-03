package burp;

import burp.error.SigCredentialProviderException;
import lombok.SneakyThrows;
import software.amazon.awssdk.utils.IoUtils;
import software.amazon.awssdk.utils.Platform;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SigCommandCredentialProvider implements SigCredentialProvider{
    private static final Pattern ACCESS_KEY_PATTERN = Pattern.compile("(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])");
    private static final Pattern SECRET_KEY_PATTERN = Pattern.compile("(?<![A-Za-z0-9/+])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])");
    private static final Pattern SESSION_TOKEN_PATTERN = Pattern.compile("(?<![A-Za-z0-9/+])(?:[A-Za-z0-9+/]){40,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})(?![A-Za-z0-9/+=])");

    public static final String PROVIDER_NAME = "CLICommand";
    protected LogWriter logger = LogWriter.getLogger();
    private String cliCommand;
    private List commandList;
    private transient SigCredential credential;

    public SigCommandCredentialProvider(String command) throws IOException, InterruptedException {
        List<String> cmd = new ArrayList<>();

        if (Platform.isWindows()) {
            cmd.add("cmd.exe");
            cmd.add("/C");
        } else {
            cmd.add("sh");
            cmd.add("-c");
        }
        cliCommand = command;
        String builderCommand = Objects.requireNonNull(command);

        cmd.add(builderCommand);
        commandList = Collections.unmodifiableList(cmd);
        try{
            renewCredential();
        } catch (Exception e) {
            throw new IllegalArgumentException(e.getMessage());
        }

    }

    // Execute the external process to retrieve credentials.
    private String executeCommand(List command) throws IOException, InterruptedException {
        ProcessBuilder processBuilder = new ProcessBuilder(command);

        ByteArrayOutputStream commandOutput = new ByteArrayOutputStream();
        ByteArrayOutputStream commandError = new ByteArrayOutputStream();


        Process process = processBuilder.start();
        try {
            IoUtils.copy(process.getInputStream(), commandOutput, 64000); //max 64KB output
            IoUtils.copy(process.getErrorStream(), commandError, 32000); //max 32KB error

            process.waitFor();

            String out = new String(commandOutput.toByteArray(), StandardCharsets.UTF_8);
            if (process.exitValue() != 0) {
                String err = "Command returned non-zero exit value: " + process.exitValue();
                logger.error(err);
                if (!out.equals("")) {
                    logger.error("Output: " + out);
                }
                logger.debug(new String(commandError.toByteArray(), StandardCharsets.UTF_8));
                throw new IllegalStateException(err);
            }
            logger.debug("Executing command: " + command);
            logger.debug(out);
            return out;
        } finally {
            process.destroy();
        }
    }
    private SigCredential renewCredential() {
        credential = null;

        String output = null;
        try {
            output = executeCommand(commandList);
        } catch (InterruptedException | IOException | RuntimeException ex) {
            logger.error("Error while executing command for with command: \"" + cliCommand + "\" resulting in error: " + ex.getMessage());
            throw new SigCredentialProviderException(ex.getMessage());
        }
        Optional<SigCredential> newCredential = parseCommandOutput(output);
        if (newCredential.isPresent()) {
            logger.info("Successfully fetched credentials using command: " + cliCommand);
            credential = newCredential.get();
            return newCredential.get();
        } else {
            logger.info("No credentials extracted from the following output: " + output);
            throw new SigCredentialProviderException("No credentials extracted from command output.");
        }
    }

    private Optional<SigCredential> parseCommandOutput(String output){
        Matcher accessKeyMatcher = ACCESS_KEY_PATTERN.matcher(output);
        Matcher secretKeyMatcher = SECRET_KEY_PATTERN.matcher(output);
        if (accessKeyMatcher.find() && secretKeyMatcher.find()) {
            String accessKey = accessKeyMatcher.group();
            String secretKey = secretKeyMatcher.group();
            String sessionToken = null;

            Matcher sessionTokenMatcher = SESSION_TOKEN_PATTERN.matcher(output);
            if (sessionTokenMatcher.find()) {
                sessionToken = sessionTokenMatcher.group();
            }

            if(sessionToken != null){
                logger.info("Found temporary credentials for the following Access Key: " + accessKey);
                return Optional.of(new SigTemporaryCredential(accessKey, secretKey, sessionToken, Instant.now().getEpochSecond()+600));
            }
            logger.info("Found static credentials for the following Access Key: " + accessKey);
            return Optional.of(new SigStaticCredential(accessKey, secretKey));
        }
        return Optional.empty();

    }

    @SneakyThrows
    @Override
    public SigCredential getCredential() throws SigCredentialProviderException {
        SigCredential credentialCopy = credential;
        if (credentialCopy == null) {
            credentialCopy = renewCredential();
        }
        else {
            if (credentialCopy.isTemporary()) {
                if (SigTemporaryCredential.shouldRenewCredential(((SigTemporaryCredential)credentialCopy))) {
                    // fewer than 30 seconds until expiration, refresh
                    credentialCopy = renewCredential();
                }
            }
            else {
                // always refresh permanent credentials. seems counter-intuitive but if the user
                // isn't just using a static provider there must be a reason.
                credentialCopy = renewCredential();
            }
        }
        if (credentialCopy == null) {
            logger.error("Cannot get credentials from " + cliCommand);
            throw new SigCredentialProviderException("Failed to get credential from "+ cliCommand);
        }
        return credentialCopy;
    }

    @Override
    public String getName() {
        return PROVIDER_NAME;
    }

    @Override
    public String getClassName() {
        return getClass().getName();
    }

    public String getCommand(){
        return cliCommand;
    }
}
