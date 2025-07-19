import requests
from anthropic import Anthropic
from mistralai import Mistral
from openai import OpenAI, AzureOpenAI
import streamlit as st

from google import genai as google_genai
from groq import Groq
from utils import process_groq_response, create_reasoning_system_prompt

# Function to create a prompt to generate mitigating controls
def create_mitigations_prompt(threats):
    # Format the threats data properly for the prompt
    if isinstance(threats, list):
        # Raw threat model data - format as structured text with enhanced information
        formatted_threats = "IDENTIFIED THREATS WITH MITRE CONTEXT:\n\n"
        for i, threat in enumerate(threats, 1):
            threat_id = threat.get('Threat ID', f'STR-{i:03d}')
            formatted_threats += f"Threat {i}: {threat_id}\n"
            formatted_threats += f"- Threat Type: {threat.get('Threat Type', 'N/A')}\n"
            formatted_threats += f"- Component: {threat.get('Component', 'Not Specified')}\n"
            formatted_threats += f"- Scenario: {threat.get('Scenario', 'N/A')}\n"
            formatted_threats += f"- Potential Impact: {threat.get('Potential Impact', 'N/A')}\n"
            
            # Add MITRE information if available (from enhanced threats)
            if 'mitre_techniques' in threat and threat['mitre_techniques']:
                formatted_threats += f"- MITRE ATT&CK Techniques: "
                technique_list = []
                for technique in threat['mitre_techniques']:
                    technique_list.append(f"{technique.get('id', 'Unknown')} ({technique.get('name', 'Unknown')})")
                formatted_threats += ", ".join(technique_list) + "\n"
            
            if 'mitre_tactics' in threat and threat['mitre_tactics']:
                formatted_threats += f"- MITRE Tactics: {', '.join(threat['mitre_tactics'])}\n"
            
            # Add DREAD score if available for prioritization
            if 'Risk Score' in threat:
                formatted_threats += f"- DREAD Risk Score: {threat['Risk Score']}\n"
            
            formatted_threats += "\n"
    else:
        # Fallback for markdown or other formats
        formatted_threats = str(threats)

    prompt = f"""
Act as a cyber security expert with more than 20 years experience of using the STRIDE threat modelling methodology, MITRE ATT&CK framework, NIST Cybersecurity Framework, and CIS Controls. Your task is to provide comprehensive, actionable mitigations for the threats identified in the threat model.

Your output should be in the form of a markdown table with the following columns:
    - Column A: Threat ID
    - Column B: Threat Type  
    - Column C: Component
    - Column D: Mitigation Category (Technical/Administrative/Physical)
    - Column E: Suggested Mitigation(s)
    - Column F: MITRE Mitigation ID (if applicable, e.g., M1032)
    - Column G: NIST CSF Reference (e.g., PR.AC-1, DE.CM-1)
    - Column H: Implementation Details
    - Column I: Difficulty (Easy/Medium/Hard)
    - Column J: Timeline (Days/Weeks/Months)
    - Column K: Cost (Low/Medium/High)

MITIGATION REQUIREMENTS:
- Map each threat to relevant MITRE ATT&CK mitigations where possible (M1001-M1057)
- Include NIST Cybersecurity Framework subcategories (PR.*, DE.*, RS.*, etc.)
- Categorize as Technical (firewalls, encryption), Administrative (policies, training), or Physical (facility security)
- Provide specific, actionable implementation guidance
- Include tool/vendor recommendations where appropriate

COMMON MITRE ATT&CK MITIGATIONS FOR REFERENCE:
- M1032: Multi-factor Authentication - For authentication-related threats
- M1050: Exploit Protection - For application vulnerabilities
- M1018: User Account Management - For access control issues
- M1027: Password Policies - For credential-based threats
- M1038: Execution Prevention - For code execution threats
- M1031: Network Intrusion Prevention - For network-based attacks
- M1030: Network Segmentation - For lateral movement threats
- M1028: Operating System Configuration - For system-level threats
- M1049: Antivirus/Antimalware - For malware threats
- M1017: User Training - For social engineering threats

COMMON NIST CSF SUBCATEGORIES:
- PR.AC-1: Access Control Management
- PR.AC-4: Access Control for Networks
- PR.AT-1: Security Awareness Training
- PR.DS-1: Data Security - Data at rest
- PR.DS-2: Data Security - Data in transit
- DE.CM-1: Continuous Monitoring
- DE.CM-7: Continuous Monitoring for Personnel Activity
- RS.RP-1: Response Planning

FORMATTING REQUIREMENTS:
- Use proper markdown table format
- For multi-point mitigations in the "Suggested Mitigation(s)" column, separate each point with semicolons and ensure each point starts with a dash
- Format should be: "- First point; - Second point; - Third point"
- Keep the content clean and readable
- Preserve the Threat ID and Component information EXACTLY as provided
- Do NOT use HTML tags like <br/> as they will not render properly in the table

Below is the list of identified threats:

{formatted_threats}

EXAMPLE OUTPUT FORMAT:
| Threat ID | Threat Type | Component | Category | Suggested Mitigation(s) | MITRE ID | NIST CSF | Implementation Details | Difficulty | Timeline | Cost |
|-----------|-------------|-----------|----------|-------------------------|----------|----------|------------------------|------------|----------|------|
| STR-001 | Spoofing | Authentication Service | Technical | - Implement strong authentication protocols; - Use multi-factor authentication; - Regular security training for users | M1032 | PR.AC-1 | Deploy Azure AD MFA, configure SAML 2.0, train users on enrollment | Medium | 2-4 Weeks | Medium |

IMPORTANT GUIDANCE:
- In the "Suggested Mitigation(s)" column, separate each mitigation point with semicolons (;)
- Each point should start with a dash (-) for consistency: "- First point; - Second point"
- For MITRE Mitigation ID: Use official MITRE mitigation IDs when the threat maps to known ATT&CK techniques (separate multiple IDs with semicolons)
- For NIST CSF Reference: Use appropriate subcategories (PR.AC for Access Control, DE.CM for Continuous Monitoring, etc.) (separate multiple references with semicolons)
- For Implementation Details: Be specific about tools, configurations, and steps
- For Timeline: Consider complexity and organizational readiness

YOUR RESPONSE (do not wrap in a code block):
"""
    return prompt


# Function to get mitigations from the GPT response.
def get_mitigations(api_key, model_name, prompt):
    client = OpenAI(api_key=api_key)

    # For reasoning models (o1, o3, o3-mini, o4-mini), use a structured system prompt
    if model_name in ["o1", "o3", "o3-mini", "o4-mini"]:
        system_prompt = create_reasoning_system_prompt(
            task_description="Generate effective security mitigations for the identified threats using the STRIDE methodology.",
            approach_description="""1. Analyze each threat in the provided threat model
2. For each threat:
   - Understand the threat type and scenario
   - Consider the potential impact
   - Identify appropriate security controls and mitigations
   - Ensure mitigations are specific and actionable
3. Format the output as a markdown table with columns for:
   - Threat Type
   - Scenario
   - Suggested Mitigation(s)
4. Ensure mitigations follow security best practices and industry standards"""
        )
    else:
        system_prompt = "You are a helpful assistant that provides threat mitigation strategies in Markdown format."

    response = client.chat.completions.create(
        model = model_name,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ]
    )

    # Access the content directly as the response will be in text format
    mitigations = response.choices[0].message.content

    return mitigations


# Function to get mitigations from the Azure OpenAI response.
def get_mitigations_azure(azure_api_endpoint, azure_api_key, azure_api_version, azure_deployment_name, prompt):
    client = AzureOpenAI(
        azure_endpoint = azure_api_endpoint,
        api_key = azure_api_key,
        api_version = azure_api_version,
    )

    response = client.chat.completions.create(
        model = azure_deployment_name,
        messages=[
            {"role": "system", "content": "You are a helpful assistant that provides threat mitigation strategies in Markdown format."},
            {"role": "user", "content": prompt}
        ]
    )

    # Access the content directly as the response will be in text format
    mitigations = response.choices[0].message.content

    return mitigations

# Function to get mitigations from the Google model's response.
def get_mitigations_google(google_api_key, google_model, prompt):
    client = google_genai.Client(api_key=google_api_key)
    
    safety_settings = [
        google_genai.types.SafetySetting(
            category=google_genai.types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
            threshold=google_genai.types.HarmBlockThreshold.BLOCK_NONE
        ),
        google_genai.types.SafetySetting(
            category=google_genai.types.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
            threshold=google_genai.types.HarmBlockThreshold.BLOCK_NONE
        ),
        google_genai.types.SafetySetting(
            category=google_genai.types.HarmCategory.HARM_CATEGORY_HARASSMENT,
            threshold=google_genai.types.HarmBlockThreshold.BLOCK_NONE
        ),
        google_genai.types.SafetySetting(
            category=google_genai.types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
            threshold=google_genai.types.HarmBlockThreshold.BLOCK_NONE
        )
    ]
    
    system_instruction = "You are a helpful assistant that provides threat mitigation strategies in Markdown format."
    is_gemini_2_5 = "gemini-2.5" in google_model.lower()
    
    try:
        from google.genai import types as google_types
        if is_gemini_2_5:
            config = google_types.GenerateContentConfig(
                system_instruction=system_instruction,
                safety_settings=safety_settings,
                thinking_config=google_types.ThinkingConfig(thinking_budget=1024)
            )
        else:
            config = google_types.GenerateContentConfig(
                system_instruction=system_instruction,
                safety_settings=safety_settings
            )
        response = client.models.generate_content(
            model=google_model,
            contents=prompt,
            config=config
        )
        # Extract Gemini 2.5 'thinking' content if present
        thinking_content = []
        for candidate in getattr(response, 'candidates', []):
            content = getattr(candidate, 'content', None)
            if content and hasattr(content, 'parts'):
                for part in content.parts:
                    if hasattr(part, 'thought') and part.thought:
                        thinking_content.append(str(part.thought))
        if thinking_content:
            joined_thinking = "\n\n".join(thinking_content)
            st.session_state['last_thinking_content'] = joined_thinking
    except Exception as e:
        st.error(f"Error generating mitigations with Google AI: {str(e)}")
        return f"""
## Error Generating Mitigations

**API Error:** {str(e)}

Please try again or select a different model provider.
"""
    
    mitigations = response.text
    return mitigations

# Function to get mitigations from the Mistral model's response.
def get_mitigations_mistral(mistral_api_key, mistral_model, prompt):
    client = Mistral(api_key=mistral_api_key)

    response = client.chat.complete(
        model = mistral_model,
        messages=[
            {"role": "system", "content": "You are a helpful assistant that provides threat mitigation strategies in Markdown format."},
            {"role": "user", "content": prompt}
        ]
    )

    # Access the content directly as the response will be in text format
    mitigations = response.choices[0].message.content

    return mitigations

# Function to get mitigations from Ollama hosted LLM.
def get_mitigations_ollama(ollama_endpoint, ollama_model, prompt):
    """
    Get mitigations from Ollama hosted LLM.
    
    Args:
        ollama_endpoint (str): The URL of the Ollama endpoint (e.g., 'http://localhost:11434')
        ollama_model (str): The name of the model to use
        prompt (str): The prompt to send to the model
        
    Returns:
        str: The generated mitigations in markdown format
        
    Raises:
        requests.exceptions.RequestException: If there's an error communicating with the Ollama endpoint
        KeyError: If the response doesn't contain the expected fields
    """
    if not ollama_endpoint.endswith('/'):
        ollama_endpoint = ollama_endpoint + '/'
    
    url = ollama_endpoint + "api/chat"

    data = {
        "model": ollama_model,
        "stream": False,
        "messages": [
            {
                "role": "system", 
                "content": """You are a cyber security expert with more than 20 years experience of implementing security controls for a wide range of applications. Your task is to analyze the provided application description and suggest appropriate security controls and mitigations.

Please provide your response in markdown format with appropriate headings and bullet points."""
            },
            {
                "role": "user",
                "content": prompt
            }
        ]
    }

    try:
        response = requests.post(url, json=data, timeout=60)  # Add timeout
        response.raise_for_status()  # Raise exception for bad status codes
        outer_json = response.json()
        
        try:
            # Access the 'content' attribute of the 'message' dictionary
            mitigations = outer_json["message"]["content"]
            return mitigations
            
        except KeyError as e:

            raise
            
    except requests.exceptions.RequestException as e:

        raise

# Function to get mitigations from the Anthropic model's response.
def get_mitigations_anthropic(anthropic_api_key, anthropic_model, prompt):
    client = Anthropic(api_key=anthropic_api_key)
    
    # Check if we're using extended thinking mode
    is_thinking_mode = "thinking" in anthropic_model.lower()
    
    # If using thinking mode, use the actual model name without the "thinking" suffix
    actual_model = "claude-3-7-sonnet-latest" if is_thinking_mode else anthropic_model
    
    try:
        # Configure the request based on whether thinking mode is enabled
        if is_thinking_mode:
            response = client.messages.create(
                model=actual_model,
                max_tokens=24000,
                thinking={
                    "type": "enabled",
                    "budget_tokens": 16000
                },
                system="You are a helpful assistant that provides threat mitigation strategies in Markdown format.",
                messages=[
                    {"role": "user", "content": prompt}
                ],
                timeout=600  # 10-minute timeout
            )
        else:
            response = client.messages.create(
                model=actual_model,
                max_tokens=4096,
                system="You are a helpful assistant that provides threat mitigation strategies in Markdown format.",
                messages=[
                    {"role": "user", "content": prompt}
                ],
                timeout=300  # 5-minute timeout
            )

        # Access the text content
        if is_thinking_mode:
            # For thinking mode, we need to extract only the text content blocks
            mitigations = ''.join(block.text for block in response.content if block.type == "text")
            
            # Store thinking content in session state for debugging/transparency (optional)
            thinking_content = ''.join(block.thinking for block in response.content if block.type == "thinking")
            if thinking_content:
                st.session_state['last_thinking_content'] = thinking_content
        else:
            # Standard handling for regular responses
            mitigations = response.content[0].text

        return mitigations
    except Exception as e:
        # Handle timeout and other errors
        error_message = str(e)
        st.error(f"Error with Anthropic API: {error_message}")
        
        # Create a fallback response for timeout or other errors
        fallback_mitigations = f"""
## Error Generating Mitigations

**API Error:** {error_message}

### Suggestions:
- For complex applications, try simplifying the input or breaking it into smaller components
- If you're using extended thinking mode and encountering timeouts, try the standard model instead
- Consider reducing the complexity of the application description
"""
        return fallback_mitigations

# Function to get mitigations from LM Studio Server response.
def get_mitigations_lm_studio(lm_studio_endpoint, model_name, prompt):
    client = OpenAI(
        base_url=f"{lm_studio_endpoint}/v1",
        api_key="not-needed"  # LM Studio Server doesn't require an API key
    )

    response = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": "You are a helpful assistant that provides threat mitigation strategies in Markdown format."},
            {"role": "user", "content": prompt}
        ]
    )

    # Access the content directly as the response will be in text format
    mitigations = response.choices[0].message.content

    return mitigations

# Function to get mitigations from the Groq model's response.
def get_mitigations_groq(groq_api_key, groq_model, prompt):
    client = Groq(api_key=groq_api_key)
    response = client.chat.completions.create(
        model=groq_model,
        messages=[
            {"role": "system", "content": "You are a helpful assistant that provides threat mitigation strategies in Markdown format."},
            {"role": "user", "content": prompt}
        ]
    )

    # Process the response using our utility function
    reasoning, mitigations = process_groq_response(
        response.choices[0].message.content,
        groq_model,
        expect_json=False
    )
    
    # If we got reasoning, display it in an expander in the UI
    if reasoning:
        with st.expander("View model's reasoning process", expanded=False):
            st.write(reasoning)

    return mitigations