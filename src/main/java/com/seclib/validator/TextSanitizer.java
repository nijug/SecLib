package com.seclib.validator;

import com.seclib.config.SanitizerProperties;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.springframework.stereotype.Component;

@Component
public class TextSanitizer {

    private final PolicyFactory policy;
/* todo: html jest zapisany w bazie i przez to edycja jest tez w html, przemyśleć jak to zmienić
może jakieś sanitizer dla markdown istnije
 */
    public TextSanitizer(SanitizerProperties sanitizerProperties) {
        HtmlPolicyBuilder builder = new HtmlPolicyBuilder();

        sanitizerProperties.getAllowedElements().forEach(builder::allowElements);

        sanitizerProperties.getAllowedAttributes().forEach(attribute -> builder.allowAttributes(attribute).globally());

        if (sanitizerProperties.getAllowedProtocols() != null) {
            sanitizerProperties.getAllowedProtocols().forEach(builder::allowUrlProtocols);
        }

        this.policy = builder.toFactory();
    }

    public String sanitize(String input) {
        return policy.sanitize(input);
    }
}