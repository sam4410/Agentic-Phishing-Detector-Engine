# ========================================
# File: agents.py
# ========================================
from crewai import Agent, Task, Crew, Process
from langchain_openai import ChatOpenAI
from tools import URLAnalysisTool, ContentAnalysisTool, VisualAnalysisTool, VirusTotalTool
from config import Config

class PhishingDetectionAgents:
    """Define all agents for phishing detection"""
    
    def __init__(self):
        # CrewAI's native LLM configuration with OpenAI
        self.llm = ChatOpenAI(
            model=Config.OPENAI_MODEL_NAME,
            temperature=0.3
        )
    
    def url_analyzer_agent(self):
        return Agent(
            role='URL Security Analyst',
            goal="""
            Analyze the provided URL using the URL Analysis Tool exactly once.

            You MUST:
            - Call the URL Analysis Tool only once per input
            - Use the tool output as final and authoritative
            - Report findings exactly as returned by the tool

            You MUST NOT:
            - Retry the tool
            - Re-run the same analysis
            - Attempt alternative inputs
            - Speculate beyond the tool output
            """,
            backstory="""
            You are a domain and URL security specialist.
            You identify phishing indicators such as suspicious TLDs,
            typosquatting, excessive subdomains, and malformed URLs.
            """,
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            tools=[URLAnalysisTool()]
        )
    
    def content_analyzer_agent(self):
        return Agent(
            role="Content Security Analyst",
            goal="""
            Analyze the provided email or webpage content using the Content Analysis Tool
            exactly once.

            You MUST:
            - Call the Content Analysis Tool only once per input
            - Treat the tool output as final and authoritative
            - Report findings exactly as returned by the tool

            You MUST NOT:
            - Retry the tool
            - Re-analyze the same content
            - Speculate beyond the tool output
            - Assume malicious intent without evidence
            """,
            backstory="""
            You are a cybersecurity analyst specializing in social engineering detection.
            You identify observable phishing indicators such as urgency language,
            threats, generic greetings, and manipulative wording.
            You report factual findings only.
            """,
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            tools=[ContentAnalysisTool()]
        )
    
    def visual_analyzer_agent(self):
        return Agent(
            role="Visual Security Analyst",
            goal="""
            Analyze the visual and structural characteristics of the provided webpage
            using the Visual Analysis Tool exactly once.

            You MUST:
            - Call the Visual Analysis Tool only once per input
            - Treat the tool output as final and authoritative
            - Report findings exactly as returned by the tool

            You MUST NOT:
            - Retry the tool
            - Attempt alternative URLs or inputs
            - Speculate beyond the tool output
            - Assume malicious intent without evidence
            """,
            backstory="""
            You are a web security specialist focused on detecting visual phishing indicators
            such as fake login forms, brand impersonation, deceptive layouts, and suspicious
            external resource usage. You report observable facts only.
            """,
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            tools=[VisualAnalysisTool()]
        )
        
    def threat_intel_agent(self):
        return Agent(
            role="Threat Intelligence Analyst",
            goal="""
            Retrieve and report external threat intelligence evidence for given indicators.

            You MUST:
            - Use external threat intelligence tools (e.g. VirusTotal) to collect evidence
            - Return ONLY factual, verifiable evidence statements
            - Report evidence exactly as provided by tools
            - Explicitly report when threat intelligence verdicts are pending or unavailable

            You MUST NOT:
            - Speculate or infer malicious activity
            - Retry the same tool repeatedly
            - Assume malicious or benign status without evidence
            - Fabricate or paraphrase threat intelligence findings
            """,
            backstory="""
            You are a cybersecurity threat intelligence analyst.
            Your responsibility is to collect and report verifiable evidence
            from authoritative external sources such as VirusTotal.
            You do not perform risk scoring or final classification.
            """,
            llm=self.llm,
            tools=[VirusTotalTool()],
            verbose=True,
            allow_delegation=False
        )
    
    def coordinator_agent(self):
        return Agent(
            role='Security Coordinator',
            goal='Synthesize all security findings and output STRICT JSON ONLY providing a comprehensive threat assessment with actionable recommendations',
            backstory="""You are a senior cybersecurity analyst who coordinates 
            multiple security assessments. You synthesize findings from various 
            security tools and provide clear, actionable security recommendations.
            You output ONLY valid JSON. No reasoning. No markdown.""",
            verbose=True,
            allow_delegation=True,
            llm=self.llm
        )

class PhishingDetectionTasks:
    """Define all tasks for phishing detection"""
    
    @staticmethod
    def url_analysis_task(agent, input_data):
        return Task(
            description=f"""Analyze the following URL or domain for phishing indicators:
            
            IMPORTANT:
            - The URL Analysis Tool output is final.
            - Do not retry or re-run analysis.
            
            Input: {input_data}
            
            Use the URL Analysis Tool to perform comprehensive analysis including:
            1. Domain structure and legitimacy
            2. TLD reputation
            3. Typosquatting detection
            4. Suspicious patterns (IP addresses, excessive subdomains)
            5. URL length and character analysis
            
            Provide a detailed report with risk score (0-100).""",
            agent=agent,
            expected_output="Detailed URL analysis report with risk score and findings"
        )
    
    @staticmethod
    def content_analysis_task(agent, input_data):
        return Task(
            description=f"""Analyze the following content for phishing indicators:
            
            IMPORTANT:
            - Use the Content Analysis Tool exactly once
            - Treat the tool output as final
            
            Content: {input_data}
            
            Use the Content Analysis Tool to analyze for:
            1. Suspicious keywords and phrases
            2. Urgency and threat language
            3. Social engineering tactics
            4. Grammar and spelling issues
            5. Generic greetings and impersonal language
            
            Provide a comprehensive analysis with risk assessment.""",
            agent=agent,
            expected_output="Content analysis report identifying phishing patterns and tactics"
        )
    
    @staticmethod
    def visual_analysis_task(agent, input_data):
        return Task(
            description=f"""Analyze visual and structural indicators of phishing:
            
            IMPORTANT:
            - Use the Visual Analysis Tool exactly once
            - The tool output is final and must not be retried
            
            Input: {input_data}
            
            Use the Visual Analysis Tool to check for:
            1. Brand impersonation attempts
            2. Suspicious login or payment forms
            3. External resources and iframe usage
            4. Mismatched visual elements
            5. Fake security indicators
            
            Report all visual phishing indicators found.""",
            agent=agent,
            expected_output="Visual analysis report with brand impersonation and form security findings"
        )
        
    @staticmethod
    def threat_intel_task(agent, input_data):
        return Task(
            description=f"""
            Check this indicator against external threat intelligence sources
            such as VirusTotal, PhishTank, and OpenPhish.

            Input:
            {input_data}

            Report whether the indicator is malicious, suspicious, or clean,
            including detection counts if available.
            """,
            agent=agent,
            expected_output=(
                "Threat intelligence verdict including malicious/suspicious/harmless "
                "classification and detection counts"
            )
        )
    
    @staticmethod
    def coordination_task(agent, input_data):
        return Task(
            description=f"""
            You are a cybersecurity analysis engine.

            Analyze findings from:
            - URL Analysis Agent
            - Content Analysis Agent
            - Visual Analysis Agent
            - Threat Intelligence Agent

            🚨 CRITICAL ENFORCEMENT RULES (MANDATORY):

            1. Confirmed Threat Intelligence
            If external threat intelligence EXPLICITLY reports confirmed malicious or phishing activity
            (e.g. VirusTotal malicious detections > 0, or confirmed PhishTank/OpenPhish listing):
            - ti_confirmed MUST be true
            - phishing_probability MUST be >= 80
            - confidence MUST be >= 80
            - summary MUST clearly state that external threat intelligence confirmed the threat

            2. Suspicious but Inconclusive Threat Intelligence
            If threat intelligence reports ONLY suspicious detections (no malicious confirmations):
            - ti_confirmed MUST be false
            - phishing_probability MUST be between 50 and 79
            - summary MUST state that threat intelligence is inconclusive

            3. Pending or Unavailable Threat Intelligence
            If threat intelligence evidence is pending, unavailable, or missing:
            - ti_confirmed MUST be false
            - phishing_probability MUST be < 80
            - summary MUST state that threat intelligence verdict is pending or unavailable

            4. Anti-Fabrication Rules
            - You MUST NOT fabricate threat intelligence evidence
            - You MUST NOT claim VirusTotal, PhishTank, or OpenPhish confirmation unless explicitly stated by agents
            - All evidence entries MUST be direct factual statements derived from agent outputs

            ⚠️ OUTPUT RULES (MANDATORY):
            - Output MUST be valid JSON
            - No markdown
            - No explanations outside JSON
            - No comments
            - All booleans must be true/false
            - All numbers must be integers

            ✅ JSON SCHEMA:
            {{
              "phishing_probability": 0-100,
              "brand_impersonation_detected": true | false,
              "ti_confirmed": true | false,
              "confidence": 0-100,
              "evidence": ["string"],
              "top_findings": ["string"],
              "recommendations": ["string"],
              "summary": "string"
            }}

            Analyze this input:
            {input_data}

            Return ONLY the JSON object.
            """,
            agent=agent,
            expected_output="Strict JSON with phishing facts only"
        )

class PhishingDetectionCrew:
    """Main crew orchestration"""
    
    def __init__(self):
        self.agents = PhishingDetectionAgents()
    
    def analyze(self, input_data: str, input_type: str):
        """Run the complete phishing analysis"""
        
        # Initialize agents
        url_agent = self.agents.url_analyzer_agent()
        content_agent = self.agents.content_analyzer_agent()
        visual_agent = self.agents.visual_analyzer_agent()
        threat_agent = self.agents.threat_intel_agent()
        coordinator = self.agents.coordinator_agent()
        
        # Create tasks
        tasks = []
        agents_list = []
        
        if input_type in ['url', 'website']:
            tasks.append(PhishingDetectionTasks.url_analysis_task(url_agent, input_data))
            tasks.append(PhishingDetectionTasks.visual_analysis_task(visual_agent, input_data))
            tasks.append(PhishingDetectionTasks.threat_intel_task(threat_agent, input_data))
            agents_list.extend([url_agent, visual_agent, threat_agent])
        
        if input_type in ['email', 'content']:
            tasks.append(PhishingDetectionTasks.content_analysis_task(content_agent, input_data))
            agents_list.append(content_agent)
        
        # Always add coordination task
        tasks.append(PhishingDetectionTasks.coordination_task(coordinator, input_data))
        agents_list.append(coordinator)
        
        # Create and run crew
        crew = Crew(
            agents=agents_list,
            tasks=tasks,
            process=Process.sequential,
            verbose=True
        )
        
        result = crew.kickoff()
        return result
