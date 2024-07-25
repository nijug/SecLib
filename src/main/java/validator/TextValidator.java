package validator;

import java.util.regex.Pattern;
import java.util.logging.Logger;

import com.seclib.config.ValidatorProperties;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.springframework.beans.factory.annotation.Autowired;

public class TextValidator {

    private static final Logger logger = Logger.getLogger(TextValidator.class.getName());
    private Pattern SQL_INJECTION_PATTERN;
    private Pattern XSS_PATTERN;
    private Pattern ALLOWED_HTML_TAGS_PATTERN;
    private Pattern JAVASCRIPT_URL_PATTERN;

    public TextValidator(ValidatorProperties validatorProperties) {
        this.SQL_INJECTION_PATTERN = Pattern.compile(validatorProperties.getPatterns().getSqlInjection(), Pattern.CASE_INSENSITIVE);
        this.XSS_PATTERN = Pattern.compile(validatorProperties.getPatterns().getXss(), Pattern.CASE_INSENSITIVE);
        this.ALLOWED_HTML_TAGS_PATTERN = Pattern.compile(validatorProperties.getPatterns().getAllowedHtmlTags(), Pattern.CASE_INSENSITIVE);
        this.JAVASCRIPT_URL_PATTERN = Pattern.compile(validatorProperties.getPatterns().getJavascriptUrl(), Pattern.CASE_INSENSITIVE);
    }

    private boolean validateSQLInjection(String text) {
        boolean isValid = !SQL_INJECTION_PATTERN.matcher(text).find();
        if (!isValid) {
            logger.warning("Potential SQL Injection detected: " + text);
        }
        return isValid;
    }

    private boolean validateXSS(String text) {
        boolean isValid = !XSS_PATTERN.matcher(text).find();
        if (!isValid) {
            logger.warning("Potential XSS detected: " + text);
        }
        return isValid;
    }

    private boolean validateMarkdown(String markdown) {
        String sanitizedMarkdown = ALLOWED_HTML_TAGS_PATTERN.matcher(markdown).replaceAll("");
        boolean hasJavascriptURL = JAVASCRIPT_URL_PATTERN.matcher(sanitizedMarkdown).find();
        boolean isValid = !hasJavascriptURL;
        if (!isValid) {
            logger.warning("Potential dangerous content detected in markdown: " + markdown);
        }
        return isValid;
    }


    private String normalizeInput(String input) {
        return input.replaceAll("\\s+", " ").trim();
    }

    protected boolean validateText(String text) {
        String normalizedText = normalizeInput(text);
        return validateSQLInjection(normalizedText) && validateXSS(normalizedText) && validateMarkdown(normalizedText);
    }

    protected String sanitizeText(String input) {

        PolicyFactory policy = new HtmlPolicyBuilder()
                .allowElements("a", "b", "i", "u", "strong", "em", "p", "br")
                .allowUrlProtocols("http", "https")
                .allowAttributes("href").onElements("a")
                .toFactory();

        String safeInput = policy.sanitize(input);

        if (!safeInput.equals(input)) {
            logger.warning("Input was sanitized for security reasons.");
        }

        return safeInput;
    }
}