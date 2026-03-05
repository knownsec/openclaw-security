# I. Background

With the rapid evolution of AI Agent technology, open-source frameworks with automated decision-making and autonomous execution capabilities are gradually entering real business scenarios and production environments. Compared to traditional application systems, these frameworks not only handle data processing and interface calls but also possess the ability to execute local commands, access system resources, and orchestrate external services. Their system permission boundaries and security models present higher complexity.

As one of the representative projects in the open-source AI Agent ecosystem, OpenClaw rapidly gained attention from the global developer community in early 2026. The project runs as a chatbot, supporting natural language command input through web pages and instant messaging tools, enabling high-privilege tasks including email processing, calendar management, browser control, file operations, and even Shell command execution. With local deployment capabilities and strong autonomous execution features, the project achieved rapid growth in user scale and community influence in a short period.

OpenClaw possesses the following core capability characteristics:

* Natural language-driven task execution
* Calling local or remote tool interfaces
* Accessing file systems and network resources
* Integrating third-party plugins and skill extension mechanisms

While these capabilities enhance automation efficiency and scalability, they also imply high system permissions and extensive resource access capabilities. Compared to traditional web applications, the security issues of AI Agent frameworks are no longer limited to single interface vulnerabilities or configuration errors, but present a more multi-dimensional risk structure, including:

* Control interface exposure risks
* Execution layer permission abuse risks
* Plugin ecosystem and supply chain risks
* Deployment configuration and trust boundary issues

In the context of a rapidly expanding open-source ecosystem, security governance mechanisms often lag behind the pace of feature evolution, leading to concentrated exposure of periodic risks. Therefore, it is necessary to systematically review and objectively analyze the current security status and public security incidents of OpenClaw.

# II. Project Evolution and Attack Surface Changes

## 2.1 Brief Project Development History

OpenClaw originated from a lightweight automated forwarding tool prototype, then gradually evolved into a complete AI Agent framework with task scheduling and plugin extension capabilities. During its development, the project underwent periodic brand adjustments and was finally named OpenClaw. Related naming controversies involved Anthropic. As the project's attention grew rapidly, the plugin ecosystem and community scale expanded simultaneously.

## 2.2 Attack Surface Expansion from Architecture Evolution

OpenClaw adopts a layered architecture:

* Input interface layer (Web / API / messaging channels)
* Decision layer (LLM-driven)
* Execution layer (command and tool calls)
* Plugin ecosystem layer (third-party skills)

![architecture](./images/architecture.png)

With the increase in plugin count and enhanced execution capabilities, its attack surface presents the following characteristics:

1. Increased control interface exposure risks
2. Complicated execution permission boundaries
3. Extended plugin trust chain

There is a periodic gap between the rate of attack surface expansion and the pace of security governance mechanism improvement.

# III. Internet Exposure Surface Analysis

## 3.1 Global Exposure Scale

According to ZoomEye mapping data statistics, as of March 2, 2026, there are 63,026 identifiable OpenClaw instances worldwide.

![zoomeye_dork](./images/zoomeye_dork.png)

In terms of regional distribution, China, the United States, Singapore, and other countries rank at the top in deployment volume, with China's deployment scale significantly higher than that of the United States, making it the country with the largest number of OpenClaw deployments globally.

![zoomeye_country](./images/zoomeye_country.png)

## 3.2 Deployment Mode Characteristics

The identified typical deployment modes include:

* Default port mapping deployment
* Reverse proxy deployment

Among them, default port mapping deployment accounts for 53,072 instances (85.41%), and reverse proxy deployment accounts for 4,253 instances (6.75%).

![zoomeye_port](./images/zoomeye_port.png)

# IV. Disclosed Security Vulnerabilities

## 4.1 Vulnerability Type Distribution

As of March 4, 2026, the GitHub Advisory Database has recorded as many as 245 vulnerabilities.

![openclaw_vulns](./images/openclaw_vulns.png)

We have summarized the recorded vulnerabilities, details available here: [openclaw_vulnerabilities.xlsx](openclaw_vulnerabilities.xlsx)

Statistical analysis of the recorded vulnerabilities reveals they are mainly concentrated in the following categories:

### 1. Interface and Authentication Access Control Issues

This is the most frequent vulnerability type, involving multiple third-party integration platforms (Telegram, Slack, Twilio, etc.).

* **Unauthorized API Access**: Such as Telnyx webhook missing authentication (CVE-2026-26319) and Discord authentication defects.
* **Authentication and Validation Logic Defects**: Including BlueBubbles and Twilio webhook authentication bypasses, and multiple Allowlist bypass vulnerabilities (such as iMessage, Matrix, Voice-call).
* **Request Forgery (SSRF/CSRF)**: A total of 7 SSRF vulnerabilities, mainly concentrated in Gateway, Image tools, and Cron Webhook, reflecting lack of strict filtering for external URL requests.

### 2. Execution Permission and Sandbox Boundary Issues

As an Agent with execution capabilities, OpenClaw poses significant risks when handling system-level commands.

* **High-risk Command Injection**: Multiple RCE and command injection vulnerabilities exist, such as Docker PATH injection (CVE-2026-24763) and sshNodeCommand injection.
* **Sandbox Escape and Privilege Escalation**: The most severe vulnerability is the CVSS 9.9 safeBins validation bypass (CVE-2026-28363), which can directly lead to sandbox escape. Additionally, it includes Docker container escape and ACP auto-approval bypass.
* **Excessive File System Access Scope**: Involving multiple directory traversal and LFI (Local File Inclusion) vulnerabilities, such as Feishu file leakage and browser upload path traversal.

### 3. Plugin and Automated Task Risks

AI Agents extend capabilities through "Skills," introducing security risks from dynamic execution.

* **Script and Environment Injection**: clawtributors script injection (CVE-2026-26323) and Skill environment variable override injection.
* **Download and Path Validation Failure**: Skill download directories are not effectively validated (CVE-2026-27008), potentially leading to malicious plugin implantation.

### 4. Information Leakage and Default Configuration Risks

* **Sensitive Credential Exposure**: Telegram bot token leakage in logs (CVE-2026-27003), and skills.status exposing keys.
* **Configuration Logic Defects**: Such as Sandbox configuration Hash issues and logic errors caused by macOS deep link truncation.
* **UI Security Risks**: Multiple stored XSS vulnerabilities exist in Control UI, potentially affecting administrator account security.

Overall, these vulnerabilities reflect that in the high-privilege AI Agent system of OpenClaw, security boundary control over external input, execution environment, and plugin ecosystem remains insufficient.

## 4.2 High-Risk Vulnerabilities

### 1. Gateway Reverse Proxy Authentication Bypass

On January 25, 2026, Twitter user theonejvo discovered an unauthorized vulnerability in OpenClaw under Nginx reverse proxy scenarios. OpenClaw defaults to allowing "local connections," so when deployed on reverse proxy servers such as Nginx/Caddy, all requests appear to come from the backend 127.0.0.1. This way, it is treated as a trusted local connection. However, if the trustedProxies configuration is incorrect or forced authentication is enabled, any user can directly access the control interface, which has high privileges for proxy configuration, credential storage, conversation history, and command execution. Ultimately, this vulnerability evolved into complete control of the AI agent.

![unauthorized_access_to_configuration](./images/unauthorized_access_to_configuration.png)

### 2. 1-Click Gateway Address Modification RCE (CVE-2026-25253)

On February 1, 2026, security company DepthFirst published a blog post disclosing a high-risk vulnerability in OpenClaw that allows arbitrary modification of the gateway address. App-settings.ts directly accepts query parameters from gatewayUrl and saves them to local storage. Once a new gateway is set, the application immediately attempts to establish a connection and sends the authToken to that gateway during the handshake process. Attackers can exploit this process to build a complete attack chain: victims click carefully crafted phishing links without their knowledge, and attackers can start from stealing tokens, access local port 18789 through WebSocket connections, and ultimately achieve arbitrary command execution.

![1_click_get_gateway_token](./images/1_click_get_gateway_token.png)

### 3. ClawJacked WebSocket Brute Force (CVE-2026-25593)

On February 26, 2026, security company Oasis Security disclosed a high-risk vulnerability named ClawJacked. This vulnerability exists because the OpenClaw gateway service defaults to binding to localhost, exposing the WebSocket interface. Since browser same-origin policy does not prevent WebSocket connections to localhost, malicious websites visited by OpenClaw users can use JavaScript to silently open connections to the local gateway and attempt authentication, **without triggering any warnings**. Researchers found they could brute force OpenClaw admin passwords hundreds of times per second, **without limiting or recording failed attempts.** Once the correct password is guessed, attackers can silently register as a trusted device, because the gateway automatically approves device pairing from localhost without user confirmation.

![clawjacked](./images/clawjacked.png)

# V. Public Security Incidents

### 5.1 Email Analysis Indirect Prompt Injection

On January 27, 2026, X platform user Matvey Kukuy posted a warning about prompt injection risks in OpenClaw and its automated email agent. Attackers only need to send an email containing malicious commands to the bot and induce it to actively read the email content. The prompt in the email can then be executed as system commands, thereby manipulating the agent to access local or remote resources and exfiltrate sensitive information. In their demonstration, after being induced to read the attack email, the bot extracted and returned sensitive data such as private keys from the compromised machine. The entire attack process took only a few minutes. This case shows that when agents can automatically access emailboxes, files, or system resources, once isolation and validation of external input is lacking, prompt injection can be exploited as a remote control entry, leading to sensitive data leakage or even complete host takeover.

![email_prompt_injection](./images/email_prompt_injection.png)

### 5.2 Plugin Market Distributing Malicious Skills to Steal Data

On February 1, 2026, Koi Security researcher Oren Yomtov discovered 341 malicious skills in the official OpenClaw plugin market ClawHub, naming this malicious attack: ClawHavoc. These skills disguise themselves as commonly used tools, downloading encrypted archives containing macOS/Windows trojans, such as Atomic macOS Stealer. Once activated, they can steal sensitive data such as user emailboxes, login tokens, and API keys. This event shows that skills bring a new technical paradigm. Without strict review and control, high-privilege agents often become a double-edged sword, becoming a springboard for hacker attacks.

![clawhavoc](./images/clawhavoc.png)

### 5.3 Moltbook Community Database Exposure Leading to Agent Takeover Risk

On February 2, 2026, security company Wiz disclosed that the Moltbook security community in the OpenClaw ecosystem had serious database configuration errors: the Supabase database used by the platform did not enable row-level access control (RLS), and the public API Key was granted full table read-write permissions, resulting in the database being almost completely open to the outside. Attackers only need to use this API Key to directly access and modify platform data.

This vulnerability led to the exposure of approximately 1.5 million sets of API and authentication tokens, 35,000 user emailboxes, login tokens, and private message content. More seriously, attackers can use the leaked authentication information to take over AI agent accounts on the platform, or even impersonate agents with large numbers of followers to publish content or execute tasks.

This incident exposes serious defects in the OpenClaw ecosystem regarding platform access control and key permission management. Since agents have automatic publishing and task execution capabilities, once an account is hijacked, attackers can implant malicious commands in task chains, thereby further triggering automated attacks or malicious operations, forming control risks over the entire platform agent ecosystem.

![moltbook_supabase](./images/moltbook_supabase.png)

### 5.4 Web Scraping Indirect Prompt Injection

On February 3, 2026, researchers from security research firm HiddenLayer published a report detailing the indirect prompt injection risks in OpenClaw's web scraping mode. Attackers implant hidden malicious commands in web pages, documents, or HTML source code (such as hiding in `<think>` tags or transparent text), inducing OpenClaw agents that are summarizing web page content to deviate from their original tasks. In actual attack demonstrations, these commands tamper with the agent's core configuration file SOUL.md, establishing a persistent "AI backdoor" for attackers. Hijacked agents silently exfiltrate user session data, API tokens, and private keys to the attacker's server. This incident reveals that when AI agents process external untrusted data, if they lack physical isolation between "data" and "commands," their automated processing capabilities will be directly converted into remote control entries for attackers.

![web_fetch_injection](./images/web_fetch_injection.png)

### 5.5 Accidental Deletion of Meta Security Director's Email

On February 23, 2026, Meta Super Intelligence Team Security Director Summer Yue experienced agent失控 when using an OpenClaw agent to clean her personal emailbox: the AI ignored the "wait for confirmation" instruction and began batch deleting emails on its own. Before she urgently returned to her device to force termination, the agent had deleted over 200 emails. This incident exposes the failure of agent operation control, fully relying on model judgment rather than hard blocking mechanisms when executing sensitive operations.

![delete_email](./images/delete_email.png)

# VI. Conclusion

With the rapid development of AI Agent technology, OpenClaw, as a representative of open-source agent frameworks, demonstrates highly automated task execution and extensive resource access capabilities. However, its high-privilege characteristics also bring complex and multi-level security risks. Through systematic analysis of the OpenClaw project's architecture evolution, internet exposure surface, disclosed vulnerabilities, and public security incidents, this article reveals the following key issues:

1. **Access Control and Permission Management Deficiencies**
    Most vulnerabilities are concentrated in interface authentication failures, excessive API permissions, and loose execution layer sandbox boundaries, allowing attackers to directly exploit unauthorized interfaces to obtain sensitive data or control agents.

2. **Plugin and Automated Task Risks**
    Third-party skill extensions and automated task chains provide agents with flexible capabilities, but vulnerabilities such as missing plugin download directory validation, environment variable override, and script injection make agents easy to become attack vectors.

3. **Information Leakage and Configuration Errors**
    Issues such as databases not enabling RLS, sensitive credential exposure in logs, and insecure default configurations lead to large-scale leakage of user emailboxes, API keys, login tokens, and private messages. Attackers can take over agent accounts and implant malicious task chains.

4. **Insufficient Agent Autonomous Execution Control**
    Actual incidents show that when AI agents fully rely on model judgment and lack hard operation blocking, misoperations or remote exploitation may occur, such as the email batch deletion incident and prompt injection attack cases.

In summary, OpenClaw's security incidents and vulnerabilities reflect the contradiction between rapid feature iteration and lagging security governance in AI Agent systems. In the future, stricter security policies need to be established for **access control, execution permission isolation, plugin auditing, and automated task security mechanisms** to ensure agent controllability and trustworthiness in real production environments.

# VII. References

1. OpenClaw ZoomEye search link: https://www.zoomeye.org/searchResult?q=YXBwPSJPcGVuQ2xhdyI%3D
2. Gateway reverse proxy authentication bypass: https://x.com/theonejvo/status/2015401219746128322
3. 1-Click gateway address modification RCE (CVE-2026-25253): https://depthfirst.com/post/1-click-rce-to-steal-your-moltbot-data-and-keys
4. ClawJacked WebSocket brute force (CVE-2026-25593): https://www.oasis.security/blog/openclaw-vulnerability
5. Email analysis indirect prompt injection: https://x.com/Mkukkk/status/2015951362270310879
6. Plugin market distributing malicious skills to steal data: https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting
7. Moltbook community database exposure leading to agent takeover risk: https://www.wiz.io/blog/exposed-moltbook-database-reveals-millions-of-api-keys
8. Web scraping indirect prompt injection: https://www.hiddenlayer.com/research/exploring-the-security-risks-of-ai-assistants-like-openclaw
9. Accidental deletion of Meta security director's email: https://x.com/summeryue0/status/2025774069124399363
