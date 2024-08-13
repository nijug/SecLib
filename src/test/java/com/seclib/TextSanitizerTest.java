package com.seclib;

import com.seclib.config.SanitizerProperties;
import com.seclib.validator.TextSanitizer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import static org.mockito.Mockito.when;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

public class TextSanitizerTest {

    @Mock
    private SanitizerProperties sanitizerProperties;

    private TextSanitizer textSanitizer;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);

        when(sanitizerProperties.getAllowedElements()).thenReturn(List.of("a", "b", "p"));
        when(sanitizerProperties.getAllowedAttributes()).thenReturn(List.of("href"));
        when(sanitizerProperties.getAllowedProtocols()).thenReturn(List.of("http", "https"));

        textSanitizer = new TextSanitizer(sanitizerProperties);
    }

    @Test
    public void testSanitizeWithAllowedElements() {
        String unsafeInput = "<a href='http://example.com'>Click here</a><script>alert('XSS');</script>";
        String expectedOutput = "<a href=\"http://example.com\">Click here</a>";
        String sanitizedOutput = textSanitizer.sanitize(unsafeInput);

        assertEquals(expectedOutput, sanitizedOutput);
    }

    @Test
    public void testSanitizeWithDisallowedAttributes() {
        String unsafeInput = "<a onclick='alert(\"XSS\")' href='http://example.com'>Click here</a>";
        String expectedOutput = "<a href=\"http://example.com\">Click here</a>";
        String sanitizedOutput = textSanitizer.sanitize(unsafeInput);

        assertEquals(expectedOutput, sanitizedOutput);
    }

    @Test
    public void testSanitizeWithDisallowedProtocols() {
        String unsafeInput = "<a href='javascript:alert(\"XSS\")'>Click here</a>";
        String expectedOutput = "Click here";
        String sanitizedOutput = textSanitizer.sanitize(unsafeInput);

        assertEquals(expectedOutput, sanitizedOutput);
    }

    @Test
    public void testSanitizeWithNestedTags() {
        String unsafeInput = "<div><a href='http://example.com'><b>Click here</b></a></div>";
        String expectedOutput = "<a href=\"http://example.com\"><b>Click here</b></a>";
        String sanitizedOutput = textSanitizer.sanitize(unsafeInput);

        assertEquals(expectedOutput, sanitizedOutput);
    }

    @Test
    public void testSanitizeWithMixedCaseTags() {
        String unsafeInput = "<A HREF='http://example.com'>Click here</A>";
        String expectedOutput = "<a href=\"http://example.com\">Click here</a>";
        String sanitizedOutput = textSanitizer.sanitize(unsafeInput);

        assertEquals(expectedOutput, sanitizedOutput);
    }

    @Test
    public void testSanitizeWithMultipleDisallowedElements() {
        String unsafeInput = "<script>alert('XSS');</script><iframe src='http://example.com'></iframe>Allowed text";
        String expectedOutput = "Allowed text";
        String sanitizedOutput = textSanitizer.sanitize(unsafeInput);

        assertEquals(expectedOutput, sanitizedOutput);
    }

    @Test
    public void testSanitizeWithValidAndInvalidProtocols() {
        String unsafeInput = "<a href='http://example.com'>Valid</a><a href='ftp://example.com'>Invalid</a>";
        String expectedOutput = "<a href=\"http://example.com\">Valid</a>Invalid";
        String sanitizedOutput = textSanitizer.sanitize(unsafeInput);

        assertEquals(expectedOutput, sanitizedOutput);
    }

    @Test
    public void testSanitizeWithNestedElements() {
        String unsafeInput = "<div><a href='http://example.com'><script>alert('XSS');</script>Click here</a></div>";
        String expectedOutput = "<a href=\"http://example.com\">Click here</a>";
        String sanitizedOutput = textSanitizer.sanitize(unsafeInput);

        assertEquals(expectedOutput, sanitizedOutput);
    }

    @Test
    public void testSanitizeEncodedEntities() {
        String unsafeInput = "Some text &lt;script&gt;alert('XSS');&lt;/script&gt;";
        String expectedOutput = "Some text &lt;script&gt;alert(&#39;XSS&#39;);&lt;/script&gt;";
        String sanitizedOutput = textSanitizer.sanitize(unsafeInput);

        assertEquals(expectedOutput, sanitizedOutput);
    }

    @Test
    public void testSanitizeWithPartialTags() {
        String unsafeInput = "Click here <a href='http://example.com'>Link</a";
        String expectedOutput = "Click here <a href=\"http://example.com\">Link</a>";
        String sanitizedOutput = textSanitizer.sanitize(unsafeInput);

        assertEquals(expectedOutput, sanitizedOutput);
    }

}
