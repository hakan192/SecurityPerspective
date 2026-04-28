import { useEffect, useId, useMemo, useRef, useState } from 'react'
import './App.css'

const resolvedHost = window.location.hostname || 'localhost'
const configuredApiBase = import.meta.env.VITE_API_BASE_URL
const API_BASE =
  configuredApiBase && configuredApiBase.includes('localhost') && !['localhost', '127.0.0.1'].includes(resolvedHost)
    ? configuredApiBase.replace('localhost', resolvedHost)
    : configuredApiBase || `http://${resolvedHost}:8000`

const SERVER_POLICY_ENDPOINT = '/fortiweb/server-policy/latest'

const navItems = [
  {
    id: 'waf',
    label: 'WAF Configuration',
    description: 'Policies, gaps, and remediation priorities'
  },
  {
    id: 'automation',
    label: 'Automation',
    description: 'Security automation controls and quick actions'
  },
  {
    id: 'overview',
    label: 'Executive Overview',
    description: 'Leadership-ready security posture summaries'
  }
]

const MAIN_WAF_TAB_ID = 'waf-main-tab'

function ShieldCheckIcon({ className = '', size = 14 }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M20 13c0 5-3.5 7.5-8 9-4.5-1.5-8-4-8-9V6l8-3 8 3z" />
      <path d="m9 12 2 2 4-4" />
    </svg>
  )
}

function ShieldAlertIcon({ className = '', size = 14 }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M20 13c0 5-3.5 7.5-8 9-4.5-1.5-8-4-8-9V6l8-3 8 3z" />
      <path d="M12 8v4" />
      <path d="M12 16h.01" />
    </svg>
  )
}

function ShieldXIcon({ className = '', size = 14 }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M20 13c0 5-3.5 7.5-8 9-4.5-1.5-8-4-8-9V6l8-3 8 3z" />
      <path d="m9 9 6 6" />
      <path d="m15 9-6 6" />
    </svg>
  )
}

function DeviceStackIcon({ className = '', size = 14 }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect width="20" height="8" x="2" y="3" rx="2" />
      <rect width="20" height="8" x="2" y="13" rx="2" />
      <path d="M6 7h.01" />
      <path d="M6 17h.01" />
    </svg>
  )
}

function getPolicyStatusVisual(status) {
  const normalized = String(status ?? '').trim().toLowerCase()
  if (normalized === 'blocking') {
    return { Icon: ShieldCheckIcon, toneClass: 'blocking' }
  }
  if (normalized === 'monitoring') {
    return { Icon: ShieldAlertIcon, toneClass: 'monitoring' }
  }
  return { Icon: ShieldXIcon, toneClass: 'not-protected' }
}

function SecurityPerspectiveLogo({ className = 'brand-logo' }) {
  const gradientId = useId()

  return (
    <svg className={className} viewBox="0 0 512 512" fill="none" xmlns="http://www.w3.org/2000/svg" aria-label="SecurityPerspective logo" role="img">
      <defs>
        <linearGradient id={gradientId} x1="112" y1="96" x2="400" y2="416" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#00A94F" />
          <stop offset="100%" stopColor="#004481" />
        </linearGradient>
      </defs>
      <rect width="512" height="512" rx="140" fill="#0F172A" />
      <path
        d="M256 110C310 110 355 125 390 150V240C390 315 340 380 256 402C172 380 122 315 122 240V150C157 125 202 110 256 110Z"
        stroke={`url(#${gradientId})`}
        strokeWidth="28"
        strokeLinejoin="round"
      />
      <ellipse cx="256" cy="250" rx="95" ry="60" stroke={`url(#${gradientId})`} strokeWidth="24" />
      <circle cx="256" cy="250" r="28" fill="#00A94F" />
    </svg>
  )
}

function LoginCard({ onLogin, darkMode, onToggleTheme }) {
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const submit = async (event) => {
    event.preventDefault()
    setError('')
    setLoading(true)
    try {
      const response = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      })
      if (!response.ok) throw new Error('Invalid username or password')
      onLogin(await response.json())
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className={`login-page ${darkMode ? 'dark' : 'light'}`}>
      <div className="login-card">
        <div className="login-head">
          <div className="brand-wrap">
            <div className="brand-logo-shell">
              <SecurityPerspectiveLogo />
            </div>
            <h1 className="brand-title">
              <span>Security</span> <span className="gradient-text">Perspective</span>
            </h1>
          </div>
          <button type="button" onClick={onToggleTheme} className="theme-btn">
            {darkMode ? 'Light' : 'Dark'}
          </button>
        </div>

        <form onSubmit={submit} className="login-form">
          <label htmlFor="username">Username</label>
          <input id="username" type="text" placeholder="Enter your username" value={username} onChange={(e) => setUsername(e.target.value)} />

          <label htmlFor="password">Password</label>
          <input id="password" type="password" placeholder="Enter your password" value={password} onChange={(e) => setPassword(e.target.value)} />

          {error && <div className="error-box">{error}</div>}

          <button className="signin-btn" disabled={loading}>
            {loading ? 'Signing in...' : 'Sign in'}
          </button>
        </form>
      </div>
    </div>
  )
}

function FullDetailsPage({ policy }) {
  if (!policy) return null

  const [customAccessExpanded, setCustomAccessExpanded] = useState(false)
  const [httpFloodExpanded, setHttpFloodExpanded] = useState(false)
  const [httpAccessLimitExpanded, setHttpAccessLimitExpanded] = useState(false)
  const [tcpFloodExpanded, setTcpFloodExpanded] = useState(false)
  const [allowMethodExpanded, setAllowMethodExpanded] = useState(false)
  const [ipListExpanded, setIpListExpanded] = useState(false)
  const [geoLocationExpanded, setGeoLocationExpanded] = useState(false)
  const [biometricDetectionExpanded, setBiometricDetectionExpanded] = useState(false)
  const [thresholdDetectionExpanded, setThresholdDetectionExpanded] = useState(false)
  const [knownBotExpanded, setKnownBotExpanded] = useState(false)

  const parseCustomAccessRule = (rule) => {
    if (!rule || typeof rule !== 'object') return null
    const rawPayload = rule.raw_json_custom_rule
    let parsedRawPayload = rawPayload
    if (typeof rawPayload === 'string') {
      try {
        parsedRawPayload = JSON.parse(rawPayload)
      } catch {
        parsedRawPayload = {}
      }
    }
    if (!parsedRawPayload || typeof parsedRawPayload !== 'object') {
      parsedRawPayload = {}
    }
    const rawResult =
      parsedRawPayload?.results?.[0] ??
      parsedRawPayload?.result?.[0] ??
      parsedRawPayload?.results ??
      parsedRawPayload?.result ??
      {}
    return {
      name: rule.name || '-',
      action: rule.action || rawResult.action || '-',
      botConfirmation: rule.bot_confirmation || rawResult['bot-confirmation'] || rawResult.bot_confirmation || '-',
      botRecognition: rule.bot_recognition || rawResult['bot-recognition'] || rawResult.bot_recognition || '-',
      rawJsonCustomRule: parsedRawPayload,
      rawJsonCustomRuleText: JSON.stringify(parsedRawPayload, null, 2)
    }
  }

  const policyIp = (policy.ip || '').trim()
  const monitorMode = String(policy['monitor-mode'] ?? policy.monitor_mode ?? '').toLowerCase()
  const deviceName = policy._deviceName || policy.device_name || policy.deviceName || 'Unknown Device'
  const policyStatus = !policyIp ? 'Not Protected' : monitorMode === 'enable' ? 'Monitoring' : 'Blocking'
  const policyStatusClass = policyStatus.toLowerCase().replace(/\s+/g, '-')

  const normalizeFeatureStatus = (value) => {
    const normalized = String(value ?? '').trim().toLowerCase()
    if (['true', '1', 'yes', 'on', 'enable', 'enabled'].includes(normalized)) return 'Enabled'
    if (['false', '0', 'no', 'off', 'disable', 'disabled'].includes(normalized)) return 'Disabled'
    return 'Unknown'
  }
  const normalizePresenceStatus = (value) =>
    String(value ?? '').trim() ? 'Enabled' : 'Unknown'

  const { Icon: PolicyStatusIcon, toneClass: policyStatusTone } = getPolicyStatusVisual(policyStatus)
  const syntaxBasedDetectionStatusFields = [
    'xss_html_tag_based_status',
    'xss_html_attribute_based_status',
    'xss_javascript_function_based_status',
    'xss_javascript_variable_based_status',
    'sql_stacked_queries_status',
    'sql_embeded_queries_status',
    'sql_condition_based_status',
    'sql_arithmetic_operation_status',
    'sql_line_comments_status',
    'sql_function_based_status'
  ]

  const syntaxBasedDetectionDetails =
    policy.syntax_based_attack_detection_details ??
    policy.web_protection_profile_details?.syntax_based_attack_detection_details ??
    {}

  const syntaxEnabledCount = syntaxBasedDetectionStatusFields.reduce((enabledCount, fieldName) => {
    const normalizedValue = String(syntaxBasedDetectionDetails[fieldName] ?? '').trim().toLowerCase()
    return enabledCount + (['enable', 'enabled', 'on', 'true', '1', 'yes'].includes(normalizedValue) ? 1 : 0)
  }, 0)
  const syntaxBasedDetectionStatus = syntaxEnabledCount >= 2 ? 'Enabled' : 'Disabled'
  const customAccessRules = (
    policy.custom_access_rules ??
    policy.web_protection_profile_details?.custom_access_rules ??
    []
  )
    .map(parseCustomAccessRule)
    .filter(Boolean)
  const customAccessRuleStatus = customAccessRules.length > 0 ? 'Enabled' : 'Unknown'
  const applicationLayerDosPolicy =
    policy.application_layer_dos_prevention_policy ??
    policy.web_protection_profile_details?.application_layer_dos_prevention_policy ??
    {}
  const layer4AccessLimitRulePolicy =
    applicationLayerDosPolicy.layer4_access_limit_rule_policy ??
    applicationLayerDosPolicy['/layer4-access-limit-rule'] ??
    applicationLayerDosPolicy['layer4-access-limit-rule'] ??
    {}
  const layer4ConnectionFloodCheckRulePolicy =
    applicationLayerDosPolicy.tcp_flood_prevention_policy ??
    applicationLayerDosPolicy.layer4_connection_flood_check_rule_policy ??
    applicationLayerDosPolicy['/layer4-connection-flood-check-rule'] ??
    applicationLayerDosPolicy['layer4-connection-flood-check-rule'] ??
    {}

  const standardProtectionFeatures = [
    {
      name: 'Signature',
      status: normalizeFeatureStatus(
        policy.signature ??
          policy.web_protection_profile_details?.signature_set_status ??
          policy.signature_protection ??
          policy['signature-protection']
      )
    },
    {
      name: 'HTTP RFC',
      status: normalizeFeatureStatus(
        policy.http_rfc ??
          policy.web_protection_profile_details?.http_protocol_parameter_restriction ??
          policy.httpRfc ??
          policy['http-rfc']
      )
    },
    {
      name: 'HTTP/2 RFC control',
      status: normalizeFeatureStatus(
        policy.http2_rfc_control ??
          policy.http2RfcControl ??
          policy['http2-rfc-control']
      )
    }
  ]


  const advancedProtectionFeatures = [
    {
      name: 'Syntax Based Detection',
      status: syntaxBasedDetectionStatus
    },
    {
      name: 'Custom Access Rules',
      status: customAccessRuleStatus,
      customAccessRules
    }
  ]
  const applicationDosProtectionFeatures = [
    {
      name: 'HTTP Flood Prevention',
      status: normalizePresenceStatus(
        applicationLayerDosPolicy.http_request_flood_prevention_rule ??
          policy.http_flood_prevention ??
          policy.web_protection_profile_details?.http_flood_prevention ??
          policy['http-flood-prevention']
      ),
      details: {
        accessLimitInHttpSession: applicationLayerDosPolicy.access_limit_in_http_session ?? '-',
        action: applicationLayerDosPolicy.action ?? '-',
        botConfirmation: applicationLayerDosPolicy.bot_confirmation ?? '-',
        botRecognition: applicationLayerDosPolicy.bot_recognition ?? '-'
      }
    },
    {
      name: 'HTTP Access Limit',
      status: normalizePresenceStatus(
        applicationLayerDosPolicy.layer4_access_limit_rule ??
          policy.http_access_limit ??
          policy.web_protection_profile_details?.http_access_limit ??
          policy['http-access-limit']
      ),
      details: {
        accessLimitStandaloneIp:
          layer4AccessLimitRulePolicy.access_limit_standalone_ip ??
          layer4AccessLimitRulePolicy['access-limit-standalone-ip'] ??
          applicationLayerDosPolicy.access_limit_standalone_ip ??
          applicationLayerDosPolicy['access-limit-standalone-ip'] ??
          '-',
        accessLimitShareIp:
          layer4AccessLimitRulePolicy.access_limit_share_ip ??
          layer4AccessLimitRulePolicy['access-limit-share-ip'] ??
          applicationLayerDosPolicy.access_limit_share_ip ??
          applicationLayerDosPolicy['access-limit-share-ip'] ??
          '-',
        action:
          layer4AccessLimitRulePolicy.action ??
          applicationLayerDosPolicy.layer4_access_limit_action ??
          applicationLayerDosPolicy.action ??
          '-',
        botConfirmation:
          layer4AccessLimitRulePolicy.bot_confirmation ??
          applicationLayerDosPolicy.layer4_access_limit_bot_confirmation ??
          applicationLayerDosPolicy.bot_confirmation ??
          '-',
        botRecognition:
          layer4AccessLimitRulePolicy.bot_recognition ??
          applicationLayerDosPolicy.layer4_access_limit_bot_recognition ??
          applicationLayerDosPolicy.bot_recognition ??
          '-'
      }
    },
    {
      name: 'TCP Flood Prevention',
      status: normalizePresenceStatus(
        applicationLayerDosPolicy.layer4_connection_flood_check_rule ??
          policy.tcp_flood_prevention ??
          policy.web_protection_profile_details?.tcp_flood_prevention ??
          policy['tcp-flood-prevention']
      ),
      details: {
        layer4ConnectionThreshold:
          layer4ConnectionFloodCheckRulePolicy.layer4_connection_threshold ??
          layer4ConnectionFloodCheckRulePolicy['layer4-connection-threshold'] ??
          applicationLayerDosPolicy.layer4_connection_threshold ??
          applicationLayerDosPolicy['layer4-connection-threshold'] ??
          '-',
        action:
          layer4ConnectionFloodCheckRulePolicy.action ??
          applicationLayerDosPolicy.layer4_connection_flood_check_action ??
          '-'
      }
    }
  ]
  const biometricBasedDetectionDetails =
    policy.web_protection_profile_details?.application_layer_dos_prevention_policy?.bot_mitigate_policy_detail?.biometric_based_detection_details ??
    policy.web_protection_profile_details?.bot_mitigate_policy_detail?.biometric_based_detection_details ??
    policy.web_protection_profile_details?.biometric_based_detection_details ??
    policy.bot_mitigate_policy_detail?.biometric_based_detection_details ??
    policy.biometric_based_detection_details ??
    {}
  const resolveBiometricDetail = (...values) => {
    const resolved = values.find((value) => value !== null && value !== undefined && String(value).trim() !== '')
    return resolved ?? '-'
  }
  const biometricDetails = {
    action: resolveBiometricDetail(
      biometricBasedDetectionDetails.action,
      biometricBasedDetectionDetails['action']
    ),
    host: resolveBiometricDetail(
      biometricBasedDetectionDetails.host,
      biometricBasedDetectionDetails['host']
    ),
    mouseMovement: resolveBiometricDetail(
      biometricBasedDetectionDetails.mouse_movement,
      biometricBasedDetectionDetails['mouse-movement'],
      biometricBasedDetectionDetails.mouseMovement
    ),
    pageFocus: resolveBiometricDetail(
      biometricBasedDetectionDetails.page_focus,
      biometricBasedDetectionDetails['page-focus'],
      biometricBasedDetectionDetails.pageFocus
    ),
    keyboard: resolveBiometricDetail(
      biometricBasedDetectionDetails.keyboard
    ),
    screenTouch: resolveBiometricDetail(
      biometricBasedDetectionDetails.screen_touch,
      biometricBasedDetectionDetails['screen-touch'],
      biometricBasedDetectionDetails.screenTouch
    ),
    scroll: resolveBiometricDetail(
      biometricBasedDetectionDetails.scroll
    ),
    botTraits: resolveBiometricDetail(
      biometricBasedDetectionDetails.bot_traits,
      biometricBasedDetectionDetails['bot-traits'],
      biometricBasedDetectionDetails.botTraits
    ),
    botTraitsNum: resolveBiometricDetail(
      biometricBasedDetectionDetails.bot_traits_num,
      biometricBasedDetectionDetails['bot-traits-num'],
      biometricBasedDetectionDetails.botTraitsNum
    )
  }
  const biometricHasValues = Object.values(biometricDetails).some((value) => value !== '-')
  const thresholdBasedDetectionDetails =
    policy.web_protection_profile_details?.application_layer_dos_prevention_policy?.bot_mitigate_policy_detail?.threshold_based_detection_details ??
    policy.web_protection_profile_details?.bot_mitigate_policy_detail?.threshold_based_detection_details ??
    policy.web_protection_profile_details?.threshold_based_detection_details ??
    policy.bot_mitigate_policy_detail?.threshold_based_detection_details ??
    policy.threshold_based_detection_details ??
    {}
  const thresholdDetails = {
    botConfirmation: resolveBiometricDetail(
      thresholdBasedDetectionDetails.bot_confirmation,
      thresholdBasedDetectionDetails['bot-confirmation'],
      thresholdBasedDetectionDetails.botConfirmation
    ),
    botRecognition: resolveBiometricDetail(
      thresholdBasedDetectionDetails.bot_recognition,
      thresholdBasedDetectionDetails['bot-recognition'],
      thresholdBasedDetectionDetails.botRecognition
    ),
    crawlerDetection: resolveBiometricDetail(
      thresholdBasedDetectionDetails.crawler_detection,
      thresholdBasedDetectionDetails['crawler-detection'],
      thresholdBasedDetectionDetails.crawlerDetection
    ),
    crawlerAction: resolveBiometricDetail(
      thresholdBasedDetectionDetails.crawler_action,
      thresholdBasedDetectionDetails['crawler-action'],
      thresholdBasedDetectionDetails.crawlerAction
    ),
    crawlerOccurrenceNum: resolveBiometricDetail(
      thresholdBasedDetectionDetails.crawler_occurrence_num,
      thresholdBasedDetectionDetails['crawler-occurrence-num'],
      thresholdBasedDetectionDetails.crawlerOccurrenceNum
    ),
    crawlerWithin: resolveBiometricDetail(
      thresholdBasedDetectionDetails.crawler_within,
      thresholdBasedDetectionDetails['crawler-within'],
      thresholdBasedDetectionDetails.crawlerWithin
    ),
    slowAttackDetection: resolveBiometricDetail(
      thresholdBasedDetectionDetails.slow_attack_detection,
      thresholdBasedDetectionDetails['slow-attack-detection'],
      thresholdBasedDetectionDetails.slowAttackDetection
    ),
    slowAttackAction: resolveBiometricDetail(
      thresholdBasedDetectionDetails.slow_attack_action,
      thresholdBasedDetectionDetails['slow-attack-action'],
      thresholdBasedDetectionDetails.slowAttackAction
    ),
    slowAttackOccurrenceNum: resolveBiometricDetail(
      thresholdBasedDetectionDetails.slow_attack_occurrence_num,
      thresholdBasedDetectionDetails['slow-attack-occurrence-num'],
      thresholdBasedDetectionDetails.slowAttackOccurrenceNum
    ),
    slowAttackWithin: resolveBiometricDetail(
      thresholdBasedDetectionDetails.slow_attack_within,
      thresholdBasedDetectionDetails['slow-attack-within'],
      thresholdBasedDetectionDetails.slowAttackWithin
    )
  }
  const thresholdHasValues = Object.values(thresholdDetails).some((value) => value !== '-')
  const knownBotsDetailsPayload =
    policy.web_protection_profile_details?.application_layer_dos_prevention_policy?.bot_mitigate_policy_detail?.known_bots_details ??
    policy.web_protection_profile_details?.bot_mitigate_policy_detail?.known_bots_details ??
    policy.web_protection_profile_details?.known_bots_details ??
    policy.bot_mitigate_policy_detail?.known_bots_details ??
    policy.known_bots_details ??
    {}
  const knownBotsDetails = {
    dos: resolveBiometricDetail(
      knownBotsDetailsPayload.dos_status,
      knownBotsDetailsPayload['dos-status'],
      knownBotsDetailsPayload.dos
    ),
    dosAction: resolveBiometricDetail(
      knownBotsDetailsPayload.dos_action,
      knownBotsDetailsPayload['dos-action'],
      knownBotsDetailsPayload.dosAction
    ),
    spam: resolveBiometricDetail(
      knownBotsDetailsPayload.spam_status,
      knownBotsDetailsPayload['spam-status'],
      knownBotsDetailsPayload.spam
    ),
    spamAction: resolveBiometricDetail(
      knownBotsDetailsPayload.spam_action,
      knownBotsDetailsPayload['spam-action'],
      knownBotsDetailsPayload.spamAction
    ),
    trojan: resolveBiometricDetail(
      knownBotsDetailsPayload.trojan_status,
      knownBotsDetailsPayload['trojan-status'],
      knownBotsDetailsPayload.trojan
    ),
    trojanAction: resolveBiometricDetail(
      knownBotsDetailsPayload.trojan_action,
      knownBotsDetailsPayload['trojan-action'],
      knownBotsDetailsPayload.trojanAction
    ),
    scanner: resolveBiometricDetail(
      knownBotsDetailsPayload.scanner_status,
      knownBotsDetailsPayload['scanner-status'],
      knownBotsDetailsPayload.scanner
    ),
    scannerAction: resolveBiometricDetail(
      knownBotsDetailsPayload.scanner_action,
      knownBotsDetailsPayload['scanner-action'],
      knownBotsDetailsPayload.scannerAction
    ),
    crawler: resolveBiometricDetail(
      knownBotsDetailsPayload.crawler_status,
      knownBotsDetailsPayload['crawler-status'],
      knownBotsDetailsPayload.crawler
    ),
    crawlerAction: resolveBiometricDetail(
      knownBotsDetailsPayload.crawler_action,
      knownBotsDetailsPayload['crawler-action'],
      knownBotsDetailsPayload.crawlerAction
    ),
    knownEngines: resolveBiometricDetail(
      knownBotsDetailsPayload.known_engines_status,
      knownBotsDetailsPayload['known-engines-status'],
      knownBotsDetailsPayload.knownEngines
    ),
    knownEnginesAction: resolveBiometricDetail(
      knownBotsDetailsPayload.known_engines_action,
      knownBotsDetailsPayload['known-engines-action'],
      knownBotsDetailsPayload.knownEnginesAction
    )
  }
  const isEnabledValue = (value) =>
    ['true', '1', 'yes', 'on', 'enable', 'enabled'].includes(String(value ?? '').trim().toLowerCase())
  const knownBotsHasEnabledControl = [
    knownBotsDetails.dos,
    knownBotsDetails.spam,
    knownBotsDetails.trojan,
    knownBotsDetails.scanner,
    knownBotsDetails.crawler,
    knownBotsDetails.knownEngines
  ].some(isEnabledValue)
  const botMitigationFeatures = [
    {
      name: 'Biometric Based Detection',
      status: biometricHasValues ? 'Enabled' : 'Unknown',
      details: biometricDetails
    },
    {
      name: 'Threshold Based Detection',
      status: thresholdHasValues ? 'Enabled' : 'Unknown',
      details: thresholdDetails
    },
    {
      name: 'Known-Bot',
      status: knownBotsHasEnabledControl ? 'Enabled' : 'Unknown',
      details: knownBotsDetails
    }
  ]
  const accessFeatures = [
    {
      name: 'Allow method',
      status: normalizePresenceStatus(
        policy.allow_method ??
          policy.allow_method_display ??
          policy.allowMethod ??
          policy['allow-method'] ??
          policy.web_protection_profile_details?.allow_method ??
          policy.web_protection_profile_details?.allow_method_display ??
          policy.web_protection_profile_details?.allowMethod ??
          policy.web_protection_profile_details?.['allow-method']
      ),
      details: {
        method:
          policy.allow_method ??
          policy.allow_method_display ??
          policy.allowMethod ??
          policy['allow-method'] ??
          (Array.isArray(policy.allow_method_list) ? policy.allow_method_list.join(', ') : null) ??
          policy.web_protection_profile_details?.allow_method ??
          policy.web_protection_profile_details?.allow_method_display ??
          (Array.isArray(policy.web_protection_profile_details?.allow_method_list)
            ? policy.web_protection_profile_details.allow_method_list.join(', ')
            : null) ??
          policy.web_protection_profile_details?.allowMethod ??
          policy.web_protection_profile_details?.['allow-method'] ??
          '-'
      }
    }
  ]
  const ipListPolicyEntries = (
    policy.ip_list_policy_entries ??
    policy.web_protection_profile_details?.ip_list_policy_entries ??
    []
  ).filter((entry) => entry && typeof entry === 'object')
  const geoIpEntries = (
    policy.geo_ip_entries ??
    policy.web_protection_profile_details?.geo_ip_entries ??
    []
  ).filter((entry) => entry && typeof entry === 'object')
  const ipProtectionFeatures = [
    {
      name: 'IP List',
      status: normalizePresenceStatus(
        ipListPolicyEntries.length > 0
          ? 'enabled'
          :
        policy.ip_list ??
          policy.ipList ??
          policy['ip-list'] ??
          policy.web_protection_profile_details?.ip_list ??
          policy.web_protection_profile_details?.ipList ??
          policy.web_protection_profile_details?.['ip-list']
      ),
      details: {
        type:
          policy.ip_list_type ??
          policy.ipListType ??
          policy['ip-list-type'] ??
          policy.web_protection_profile_details?.ip_list_type ??
          policy.web_protection_profile_details?.ipListType ??
          policy.web_protection_profile_details?.['ip-list-type'] ??
          '-',
        groupType:
          policy.ip_list_group_type ??
          policy.ipListGroupType ??
          policy['ip-list-group-type'] ??
          policy.web_protection_profile_details?.ip_list_group_type ??
          policy.web_protection_profile_details?.ipListGroupType ??
          policy.web_protection_profile_details?.['ip-list-group-type'] ??
          '-',
        ip:
          policy.ip_list ??
          policy.ipList ??
          policy['ip-list'] ??
          (Array.isArray(policy.ip_list_entries) ? policy.ip_list_entries.join(', ') : null) ??
          policy.web_protection_profile_details?.ip_list ??
          policy.web_protection_profile_details?.ipList ??
          (Array.isArray(policy.web_protection_profile_details?.ip_list_entries)
            ? policy.web_protection_profile_details.ip_list_entries.join(', ')
            : null) ??
          policy.web_protection_profile_details?.['ip-list'] ??
          '-',
        ipGroup:
          policy.ip_group ??
          policy.ipGroup ??
          policy['ip-group'] ??
          (Array.isArray(policy.ip_group_list) ? policy.ip_group_list.join(', ') : null) ??
          policy.web_protection_profile_details?.ip_group ??
          policy.web_protection_profile_details?.ipGroup ??
          (Array.isArray(policy.web_protection_profile_details?.ip_group_list)
            ? policy.web_protection_profile_details.ip_group_list.join(', ')
            : null) ??
          policy.web_protection_profile_details?.['ip-group'] ??
          '-',
        ipExternal:
          policy.ip_external ??
          policy.ipExternal ??
          policy['ip-external'] ??
          (Array.isArray(policy.ip_external_list) ? policy.ip_external_list.join(', ') : null) ??
          policy.web_protection_profile_details?.ip_external ??
          policy.web_protection_profile_details?.ipExternal ??
          (Array.isArray(policy.web_protection_profile_details?.ip_external_list)
            ? policy.web_protection_profile_details.ip_external_list.join(', ')
            : null) ??
          policy.web_protection_profile_details?.['ip-external'] ??
          '-',
        entries: ipListPolicyEntries.map((entry) => ({
          type: entry.type || '-',
          groupType: entry.group_type || entry.groupType || '-',
          ip: entry.ip || '-',
          ipGroup: entry.ip_group || entry.ipGroup || '-',
          ipExternal: entry.ip_external || entry.ipExternal || '-'
        }))
      }
    },
    {
      name: 'Geo Location',
      status: normalizePresenceStatus(
        geoIpEntries.length > 0
          ? 'enabled'
          :
        policy.geo_location ??
          policy.geoLocation ??
          policy['geo-location'] ??
          policy.web_protection_profile_details?.geo_location ??
          policy.web_protection_profile_details?.geoLocation ??
          policy.web_protection_profile_details?.['geo-location']
      ),
      details: {
        action:
          policy.geo_location_action ??
          policy.geoLocationAction ??
          policy['geo-location-action'] ??
          policy.web_protection_profile_details?.geo_location_action ??
          policy.web_protection_profile_details?.geoLocationAction ??
          policy.web_protection_profile_details?.['geo-location-action'] ??
          '-',
        countryName:
          policy.geo_location ??
          policy.geoLocation ??
          policy['geo-location'] ??
          (Array.isArray(policy.geo_location_list) ? policy.geo_location_list.join(', ') : null) ??
          policy.web_protection_profile_details?.geo_location ??
          policy.web_protection_profile_details?.geoLocation ??
          (Array.isArray(policy.web_protection_profile_details?.geo_location_list)
            ? policy.web_protection_profile_details.geo_location_list.join(', ')
            : null) ??
          policy.web_protection_profile_details?.['geo-location'] ??
          '-',
        blockPeriod:
          policy.geo_location_block_period ??
          policy.geoLocationBlockPeriod ??
          policy['geo-location-block-period'] ??
          policy.web_protection_profile_details?.geo_location_block_period ??
          policy.web_protection_profile_details?.geoLocationBlockPeriod ??
          policy.web_protection_profile_details?.['geo-location-block-period'] ??
          '-',
        entries: geoIpEntries.map((entry) => ({
          action: entry.action || '-',
          blockPeriod: entry.block_period || entry.blockPeriod || '-',
          countryName: entry.country_name || entry.countryName || '-'
        }))
      }
    }
  ]

  return (
    <section className="full-details-page">
      <div className="full-details-head">
        <div className="full-details-title-block">
          <p className="full-details-eyebrow">Server Policy</p>
          <h3>{policy.server_policy_name || 'Policy Details'}</h3>
        </div>
        <span className={`policy-status-pill ${policyStatusClass} status-pill-modern ${policyStatusTone}`}>
          <span className="policy-status-dot" aria-hidden="true" />
          <PolicyStatusIcon className="policy-status-icon" />
          <span className="policy-status-text">{policyStatus}</span>
        </span>
        <div className="full-details-device-wrap">
          <span className="policy-status-pill status-pill-modern full-details-device-pill">
            <span className="policy-status-dot" aria-hidden="true" />
            <DeviceStackIcon className="policy-status-icon" />
            <span className="policy-status-text">Device: {deviceName}</span>
          </span>
        </div>
        <p>Detailed view of selected policy configuration.</p>
      </div>

      <div className="details-sections">
        <section className="details-section">
          <header className="details-section-head">
            <h4>Standard Protection</h4>
          </header>
          <div className="details-feature-grid">
            {standardProtectionFeatures.map((feature) => (
              <article key={feature.name} className="details-feature-card">
                <div className="details-article-row">
                  <p>{feature.name}</p>
                  <span className={`details-feature-status ${feature.status.toLowerCase()}`}>
                    <span>{feature.status}</span>
                  </span>
                </div>
              </article>
            ))}
          </div>
        </section>


        <section className="details-section">
          <header className="details-section-head">
            <h4>Advance Protection</h4>
          </header>
          <div className="details-feature-grid details-feature-grid-stacked">
            {advancedProtectionFeatures.map((feature) => (
              <article
                key={feature.name}
                className={`details-feature-card ${feature.name === 'Custom Access Rules' ? 'details-feature-card-clickable' : ''}`}
                onClick={feature.name === 'Custom Access Rules' ? () => setCustomAccessExpanded((current) => !current) : undefined}
                role={feature.name === 'Custom Access Rules' ? 'button' : undefined}
                tabIndex={feature.name === 'Custom Access Rules' ? 0 : undefined}
                onKeyDown={
                  feature.name === 'Custom Access Rules'
                    ? (event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault()
                          setCustomAccessExpanded((current) => !current)
                        }
                      }
                    : undefined
                }
              >
                <div className="details-article-row">
                  <p>{feature.name}</p>
                  <span className={`details-feature-status ${feature.status.toLowerCase()}`}>
                    <span>{feature.status}</span>
                  </span>
                </div>
                {feature.name === 'Custom Access Rules' && customAccessExpanded && feature.customAccessRules?.length > 0 ? (
                  <ul className="details-sub-list">
                    {feature.customAccessRules.map((rule) => (
                      <li key={rule.name}>
                        <strong>{rule.name}</strong>
                        <span><strong>Action:</strong> <strong>{rule.action}</strong></span>
                        <span><strong>Bot confirmation:</strong> <strong>{rule.botConfirmation}</strong></span>
                        <span><strong>Bot recognition:</strong> <strong>{rule.botRecognition}</strong></span>
                        <span className="details-sub-list-meta">Raw JSON custom rule</span>
                        <pre className="details-sub-list-json">{rule.rawJsonCustomRuleText}</pre>
                      </li>
                    ))}
                  </ul>
                ) : null}
              </article>
            ))}
          </div>
        </section>

        <section className="details-section">
          <header className="details-section-head">
            <h4>Application Dos protection</h4>
          </header>
          <div className="details-feature-grid details-feature-grid-stacked">
            {applicationDosProtectionFeatures.map((feature) => (
              <article
                key={feature.name}
                className={`details-feature-card ${feature.name === 'HTTP Flood Prevention' || feature.name === 'HTTP Access Limit' || feature.name === 'TCP Flood Prevention' ? 'details-feature-card-clickable' : ''}`}
                onClick={
                  feature.name === 'HTTP Flood Prevention'
                    ? () => setHttpFloodExpanded((current) => !current)
                    : feature.name === 'HTTP Access Limit'
                      ? () => setHttpAccessLimitExpanded((current) => !current)
                      : feature.name === 'TCP Flood Prevention'
                        ? () => setTcpFloodExpanded((current) => !current)
                      : undefined
                }
                role={feature.name === 'HTTP Flood Prevention' || feature.name === 'HTTP Access Limit' || feature.name === 'TCP Flood Prevention' ? 'button' : undefined}
                tabIndex={feature.name === 'HTTP Flood Prevention' || feature.name === 'HTTP Access Limit' || feature.name === 'TCP Flood Prevention' ? 0 : undefined}
                onKeyDown={
                  feature.name === 'HTTP Flood Prevention' || feature.name === 'HTTP Access Limit' || feature.name === 'TCP Flood Prevention'
                    ? (event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault()
                          if (feature.name === 'HTTP Flood Prevention') {
                            setHttpFloodExpanded((current) => !current)
                          } else if (feature.name === 'TCP Flood Prevention') {
                            setTcpFloodExpanded((current) => !current)
                          } else {
                            setHttpAccessLimitExpanded((current) => !current)
                          }
                        }
                      }
                    : undefined
                }
              >
                <div className="details-article-row">
                  <p>{feature.name}</p>
                  <span className={`details-feature-status ${feature.status.toLowerCase()}`}>
                    <span>{feature.status}</span>
                  </span>
                </div>
                {feature.name === 'HTTP Flood Prevention' && httpFloodExpanded ? (
                  <div className="details-sub-table-wrap">
                    <table className="details-sub-table">
                      <tbody>
                        <tr>
                          <th scope="row">Access limit in HTTP session</th>
                          <td>{feature.details.accessLimitInHttpSession}</td>
                        </tr>
                        <tr>
                          <th scope="row">Action</th>
                          <td>{feature.details.action}</td>
                        </tr>
                        <tr>
                          <th scope="row">Bot confirmation</th>
                          <td>{feature.details.botConfirmation}</td>
                        </tr>
                        <tr>
                          <th scope="row">Bot recognition</th>
                          <td>{feature.details.botRecognition}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                ) : null}
                {feature.name === 'HTTP Access Limit' && httpAccessLimitExpanded ? (
                  <div className="details-sub-table-wrap">
                    <table className="details-sub-table">
                      <tbody>
                        <tr>
                          <th scope="row">Access limit standalone IP</th>
                          <td>{feature.details.accessLimitStandaloneIp}</td>
                        </tr>
                        <tr>
                          <th scope="row">Access limit share IP</th>
                          <td>{feature.details.accessLimitShareIp}</td>
                        </tr>
                        <tr>
                          <th scope="row">Action</th>
                          <td>{feature.details.action}</td>
                        </tr>
                        <tr>
                          <th scope="row">Bot confirmation</th>
                          <td>{feature.details.botConfirmation}</td>
                        </tr>
                        <tr>
                          <th scope="row">Bot recognition</th>
                          <td>{feature.details.botRecognition}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                ) : null}
                {feature.name === 'TCP Flood Prevention' && tcpFloodExpanded ? (
                  <div className="details-sub-table-wrap">
                    <table className="details-sub-table">
                      <tbody>
                        <tr>
                          <th scope="row">Layer4 connection threshold</th>
                          <td>{feature.details.layer4ConnectionThreshold}</td>
                        </tr>
                        <tr>
                          <th scope="row">Action</th>
                          <td>{feature.details.action}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                ) : null}
              </article>
            ))}
          </div>
        </section>

        <section className="details-section">
          <header className="details-section-head">
            <h4>Bot Mitigation</h4>
          </header>
          <div className="details-feature-grid details-feature-grid-stacked">
            {botMitigationFeatures.map((feature) => (
              <article
                key={feature.name}
                className={`details-feature-card ${feature.name === 'Biometric Based Detection' || feature.name === 'Threshold Based Detection' || feature.name === 'Known-Bot' ? 'details-feature-card-clickable' : ''}`}
                onClick={
                  feature.name === 'Biometric Based Detection'
                    ? () => setBiometricDetectionExpanded((current) => !current)
                    : feature.name === 'Threshold Based Detection'
                      ? () => setThresholdDetectionExpanded((current) => !current)
                      : feature.name === 'Known-Bot'
                        ? () => setKnownBotExpanded((current) => !current)
                      : undefined
                }
                role={feature.name === 'Biometric Based Detection' || feature.name === 'Threshold Based Detection' || feature.name === 'Known-Bot' ? 'button' : undefined}
                tabIndex={feature.name === 'Biometric Based Detection' || feature.name === 'Threshold Based Detection' || feature.name === 'Known-Bot' ? 0 : undefined}
                onKeyDown={
                  feature.name === 'Biometric Based Detection' || feature.name === 'Threshold Based Detection' || feature.name === 'Known-Bot'
                    ? (event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault()
                          if (feature.name === 'Biometric Based Detection') {
                            setBiometricDetectionExpanded((current) => !current)
                          } else if (feature.name === 'Threshold Based Detection') {
                            setThresholdDetectionExpanded((current) => !current)
                          } else {
                            setKnownBotExpanded((current) => !current)
                          }
                        }
                      }
                    : undefined
                }
              >
                <div className="details-article-row">
                  <p>{feature.name}</p>
                  <span className={`details-feature-status ${feature.status.toLowerCase()}`}>
                    <span>{feature.status}</span>
                  </span>
                </div>
                {feature.name === 'Biometric Based Detection' && biometricDetectionExpanded ? (
                  <div className="details-sub-table-wrap">
                    <table className="details-sub-table">
                      <tbody>
                        <tr>
                          <th scope="row">Action</th>
                          <td>{feature.details.action}</td>
                        </tr>
                        <tr>
                          <th scope="row">Host</th>
                          <td>{feature.details.host}</td>
                        </tr>
                        <tr>
                          <th scope="row">Mouse movement</th>
                          <td>{feature.details.mouseMovement}</td>
                        </tr>
                        <tr>
                          <th scope="row">Page focus</th>
                          <td>{feature.details.pageFocus}</td>
                        </tr>
                        <tr>
                          <th scope="row">Keyboard</th>
                          <td>{feature.details.keyboard}</td>
                        </tr>
                        <tr>
                          <th scope="row">Screen touch</th>
                          <td>{feature.details.screenTouch}</td>
                        </tr>
                        <tr>
                          <th scope="row">Scroll</th>
                          <td>{feature.details.scroll}</td>
                        </tr>
                        <tr>
                          <th scope="row">Bot traits</th>
                          <td>{feature.details.botTraits}</td>
                        </tr>
                        <tr>
                          <th scope="row">Bot traits num</th>
                          <td>{feature.details.botTraitsNum}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                ) : null}
                {feature.name === 'Threshold Based Detection' && thresholdDetectionExpanded ? (
                  <div className="details-sub-table-wrap">
                    <table className="details-sub-table">
                      <tbody>
                        <tr>
                          <th scope="row">Bot confirmation</th>
                          <td>{feature.details.botConfirmation}</td>
                        </tr>
                        <tr>
                          <th scope="row">Bot recognition</th>
                          <td>{feature.details.botRecognition}</td>
                        </tr>
                        <tr>
                          <th scope="row">Crawler detection</th>
                          <td>{feature.details.crawlerDetection}</td>
                        </tr>
                        <tr>
                          <th scope="row">Crawler action</th>
                          <td>{feature.details.crawlerAction}</td>
                        </tr>
                        <tr>
                          <th scope="row">Crawler occurrence num</th>
                          <td>{feature.details.crawlerOccurrenceNum}</td>
                        </tr>
                        <tr>
                          <th scope="row">Crawler within</th>
                          <td>{feature.details.crawlerWithin}</td>
                        </tr>
                        <tr>
                          <th scope="row">Slow attack detection</th>
                          <td>{feature.details.slowAttackDetection}</td>
                        </tr>
                        <tr>
                          <th scope="row">Slow attack action</th>
                          <td>{feature.details.slowAttackAction}</td>
                        </tr>
                        <tr>
                          <th scope="row">Slow attack occurrence num</th>
                          <td>{feature.details.slowAttackOccurrenceNum}</td>
                        </tr>
                        <tr>
                          <th scope="row">Slow attack within</th>
                          <td>{feature.details.slowAttackWithin}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                ) : null}
                {feature.name === 'Known-Bot' && knownBotExpanded ? (
                  <div className="details-sub-table-wrap">
                    <table className="details-sub-table">
                      <tbody>
                        <tr>
                          <th scope="row">Dos</th>
                          <td>{feature.details.dos}</td>
                        </tr>
                        <tr>
                          <th scope="row">Dos action</th>
                          <td>{feature.details.dosAction}</td>
                        </tr>
                        <tr>
                          <th scope="row">Spam</th>
                          <td>{feature.details.spam}</td>
                        </tr>
                        <tr>
                          <th scope="row">Spam action</th>
                          <td>{feature.details.spamAction}</td>
                        </tr>
                        <tr>
                          <th scope="row">Trojan</th>
                          <td>{feature.details.trojan}</td>
                        </tr>
                        <tr>
                          <th scope="row">Trojan action</th>
                          <td>{feature.details.trojanAction}</td>
                        </tr>
                        <tr>
                          <th scope="row">Scanner</th>
                          <td>{feature.details.scanner}</td>
                        </tr>
                        <tr>
                          <th scope="row">Scanner action</th>
                          <td>{feature.details.scannerAction}</td>
                        </tr>
                        <tr>
                          <th scope="row">Crawler</th>
                          <td>{feature.details.crawler}</td>
                        </tr>
                        <tr>
                          <th scope="row">Crawler action</th>
                          <td>{feature.details.crawlerAction}</td>
                        </tr>
                        <tr>
                          <th scope="row">Known engines</th>
                          <td>{feature.details.knownEngines}</td>
                        </tr>
                        <tr>
                          <th scope="row">Known engines action</th>
                          <td>{feature.details.knownEnginesAction}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                ) : null}
              </article>
            ))}
          </div>
        </section>

        <section className="details-section">
          <header className="details-section-head">
            <h4>Access</h4>
          </header>
          <div className="details-feature-grid details-feature-grid-stacked">
            {accessFeatures.map((feature) => (
              <article
                key={feature.name}
                className={`details-feature-card ${feature.name === 'Allow method' ? 'details-feature-card-clickable' : ''}`}
                onClick={feature.name === 'Allow method' ? () => setAllowMethodExpanded((current) => !current) : undefined}
                role={feature.name === 'Allow method' ? 'button' : undefined}
                tabIndex={feature.name === 'Allow method' ? 0 : undefined}
                onKeyDown={
                  feature.name === 'Allow method'
                    ? (event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault()
                          setAllowMethodExpanded((current) => !current)
                        }
                      }
                    : undefined
                }
              >
                <div className="details-article-row">
                  <p>{feature.name}</p>
                  <span className={`details-feature-status ${feature.status.toLowerCase()}`}>
                    <span>{feature.status}</span>
                  </span>
                </div>
                {feature.name === 'Allow method' && allowMethodExpanded ? (
                  <div className="details-sub-table-wrap">
                    <table className="details-sub-table">
                      <tbody>
                        <tr>
                          <th scope="row">Method</th>
                          <td>{feature.details.method}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                ) : null}
              </article>
            ))}
          </div>
        </section>

        <section className="details-section">
          <header className="details-section-head">
            <h4>IP Protection</h4>
          </header>
          <div className="details-feature-grid details-feature-grid-stacked">
            {ipProtectionFeatures.map((feature) => (
              <article
                key={feature.name}
                className={`details-feature-card ${feature.name === 'IP List' || feature.name === 'Geo Location' ? 'details-feature-card-clickable' : ''}`}
                onClick={
                  feature.name === 'IP List'
                    ? () => setIpListExpanded((current) => !current)
                    : feature.name === 'Geo Location'
                      ? () => setGeoLocationExpanded((current) => !current)
                      : undefined
                }
                role={feature.name === 'IP List' || feature.name === 'Geo Location' ? 'button' : undefined}
                tabIndex={feature.name === 'IP List' || feature.name === 'Geo Location' ? 0 : undefined}
                onKeyDown={
                  feature.name === 'IP List' || feature.name === 'Geo Location'
                    ? (event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault()
                          if (feature.name === 'IP List') {
                            setIpListExpanded((current) => !current)
                          } else {
                            setGeoLocationExpanded((current) => !current)
                          }
                        }
                      }
                    : undefined
                }
              >
                <div className="details-article-row">
                  <p>{feature.name}</p>
                  <span className={`details-feature-status ${feature.status.toLowerCase()}`}>
                    <span>{feature.status}</span>
                  </span>
                </div>
                {feature.name === 'IP List' && ipListExpanded ? (
                  <div className="details-sub-table-wrap">
                    {feature.details.entries.length > 0 ? (
                      feature.details.entries.map((entry, entryIndex) => (
                        <table className="details-sub-table" key={`${entry.ip}-${entryIndex}`}>
                          <tbody>
                            <tr>
                              <th scope="row">Type</th>
                              <td>{entry.type}</td>
                            </tr>
                            <tr>
                              <th scope="row">Group type</th>
                              <td>{entry.groupType}</td>
                            </tr>
                            <tr>
                              <th scope="row">IP</th>
                              <td>{entry.ip}</td>
                            </tr>
                            <tr>
                              <th scope="row">IP group</th>
                              <td>{entry.ipGroup}</td>
                            </tr>
                            <tr>
                              <th scope="row">IP external</th>
                              <td>{entry.ipExternal}</td>
                            </tr>
                          </tbody>
                        </table>
                      ))
                    ) : (
                      <table className="details-sub-table">
                        <tbody>
                          <tr>
                            <th scope="row">Type</th>
                            <td>{feature.details.type}</td>
                          </tr>
                          <tr>
                            <th scope="row">Group type</th>
                            <td>{feature.details.groupType}</td>
                          </tr>
                          <tr>
                            <th scope="row">IP</th>
                            <td>{feature.details.ip}</td>
                          </tr>
                          <tr>
                            <th scope="row">IP group</th>
                            <td>{feature.details.ipGroup}</td>
                          </tr>
                          <tr>
                            <th scope="row">IP external</th>
                            <td>{feature.details.ipExternal}</td>
                          </tr>
                        </tbody>
                      </table>
                    )}
                  </div>
                ) : null}
                {feature.name === 'Geo Location' && geoLocationExpanded ? (
                  <div className="details-sub-table-wrap">
                    {feature.details.entries.length > 0 ? (
                      feature.details.entries.map((entry, entryIndex) => (
                        <table className="details-sub-table" key={`${entry.countryName}-${entryIndex}`}>
                          <tbody>
                            <tr>
                              <th scope="row">Action</th>
                              <td>{entry.action}</td>
                            </tr>
                            <tr>
                              <th scope="row">Country name</th>
                              <td>{entry.countryName}</td>
                            </tr>
                            <tr>
                              <th scope="row">Block period</th>
                              <td>{entry.blockPeriod}</td>
                            </tr>
                          </tbody>
                        </table>
                      ))
                    ) : (
                      <table className="details-sub-table">
                        <tbody>
                          <tr>
                            <th scope="row">Action</th>
                            <td>{feature.details.action}</td>
                          </tr>
                          <tr>
                            <th scope="row">Country name</th>
                            <td>{feature.details.countryName}</td>
                          </tr>
                          <tr>
                            <th scope="row">Block period</th>
                            <td>{feature.details.blockPeriod}</td>
                          </tr>
                        </tbody>
                      </table>
                    )}
                  </div>
                ) : null}
              </article>
            ))}
          </div>
        </section>
      </div>
    </section>
  )
}

function AppShell({ session, onLogout, darkMode, onToggleTheme }) {
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [activeNav, setActiveNav] = useState('home')
  const [settingsExpanded, setSettingsExpanded] = useState(false)
  const [settingsGearSpinning, setSettingsGearSpinning] = useState(false)
  const [menuOpen, setMenuOpen] = useState(false)
  const [prompt, setPrompt] = useState('')
  const [searchResult, setSearchResult] = useState('')
  const [wafResponse, setWafResponse] = useState(null)
  const [loadingWaf, setLoadingWaf] = useState(false)
  const [wafError, setWafError] = useState('')
  const [selectedLocation, setSelectedLocation] = useState('All')
  const [expandedPolicyCard, setExpandedPolicyCard] = useState('')
  const [wafSearch, setWafSearch] = useState('')
  const [wafTabs, setWafTabs] = useState([{ id: MAIN_WAF_TAB_ID, title: 'WAF Configuration', type: 'main' }])
  const [activeWafTabId, setActiveWafTabId] = useState(MAIN_WAF_TAB_ID)
  const [expandedAutomationCard, setExpandedAutomationCard] = useState('')
  const [devices, setDevices] = useState([])
  const [deviceSearch, setDeviceSearch] = useState('')
  const [deviceStatusFilter, setDeviceStatusFilter] = useState('All')
  const [addDeviceModalOpen, setAddDeviceModalOpen] = useState(false)
  const [viewedDevice, setViewedDevice] = useState(null)
  const [deviceError, setDeviceError] = useState('')
  const [loadingDevices, setLoadingDevices] = useState(false)
  const [newDevice, setNewDevice] = useState({
    name: 'FortiWeb-Prod-02',
    ip: '10.10.1.25',
    environment: 'Production',
    region: 'Istanbul',
    model: 'FortiWeb VM',
    firmware: '7.4.2',
    apikey: ''
  })
  const menuRef = useRef(null)

  const username = useMemo(() => session?.username || 'admin', [session])
  const wafText = useMemo(() => JSON.stringify(wafResponse || {}), [wafResponse])
  const wafDevices = useMemo(() => {
    const devices = wafResponse?.devices
    return Array.isArray(devices) ? devices : []
  }, [wafResponse])
  const deviceRegionByName = useMemo(() => {
    const index = {}
    devices.forEach((device) => {
      index[device.name] = device.region || 'Unknown'
    })
    return index
  }, [devices])
  const locationOptions = useMemo(() => {
    const regionSet = new Set(['All'])
    wafDevices.forEach((device) => {
      regionSet.add(deviceRegionByName[device.device_name] || device.location || device.region || 'Unknown')
    })
    return Array.from(regionSet)
  }, [deviceRegionByName, wafDevices])
  const wafPolicies = useMemo(
    () =>
      wafDevices.flatMap((device) => {
        if (device.error) {
          return [{
            server_policy_name: `Error: ${device.error}`,
            _deviceName: device.device_name,
            _deviceLocation: deviceRegionByName[device.device_name] || device.location || device.region || 'Unknown'
          }]
        }
        const policies = Array.isArray(device.server_policies) ? device.server_policies : []
        return policies.map((policy) => ({
          ...policy,
          _deviceName: device.device_name,
          _deviceLocation: deviceRegionByName[device.device_name] || device.location || device.region || 'Unknown'
        }))
      }),
    [deviceRegionByName, wafDevices]
  )
  const filteredWafPolicies = useMemo(() => {
    const query = wafSearch.trim().toLowerCase()
    return wafPolicies.filter((policy) => {
      const policyLocation = (policy._deviceLocation || 'Unknown').toLowerCase()
      if (selectedLocation !== 'All' && selectedLocation.toLowerCase() !== policyLocation) return false
      if (!query) return true
      if (typeof policy === 'string') return policy.toLowerCase().includes(query)
      const policyName = (policy.server_policy_name || '').toLowerCase()
      const ip = (policy.ip || '').toLowerCase()
      const hostnames = (policy.allow_hosts_entries || [])
        .map((entry) => entry.host || '')
        .join(' ')
        .toLowerCase()
      return policyName.includes(query) || ip.includes(query) || hostnames.includes(query)
    })
  }, [wafPolicies, wafSearch, selectedLocation])
  const filteredDevices = useMemo(() => {
    const search = deviceSearch.trim().toLowerCase()
    return devices.filter((device) => {
      const statusMatch = deviceStatusFilter === 'All' || device.status === deviceStatusFilter
      if (!statusMatch) return false
      if (!search) return true
      return [device.name, device.ip, device.region, device.environment].join(' ').toLowerCase().includes(search)
    })
  }, [deviceSearch, deviceStatusFilter, devices])
  const deviceStats = useMemo(
    () => ({
      total: devices.length,
      online: devices.filter((d) => d.status === 'Online').length,
      warning: devices.filter((d) => d.status === 'Warning').length,
      offline: devices.filter((d) => d.status === 'Offline').length
    }),
    [devices]
  )

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (menuRef.current && !menuRef.current.contains(event.target)) {
        setMenuOpen(false)
      }
    }

    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const loadWafResponse = async () => {
    setLoadingWaf(true)
    setWafError('')
    try {
      const res = await fetch(`${API_BASE}${SERVER_POLICY_ENDPOINT}`)
      if (!res.ok) throw new Error('No WAF API response found. Collect from WAF first.')
      const data = await res.json()
      setWafResponse(data.payload)
    } catch (err) {
      setWafError(err.message)
    } finally {
      setLoadingWaf(false)
    }
  }

  const collectWafResponse = async () => {
    setLoadingWaf(true)
    setWafError('')
    try {
      const response = await fetch(`${API_BASE}/fortiweb/server-policy/collect`, {
        method: 'POST',
        headers: { 'X-Role': 'admin' }
      })
      if (!response.ok) throw new Error('Failed to collect WAF data from FortiWeb')
      const data = await response.json()
      setWafResponse(data.payload)
    } catch (err) {
      setWafError(err.message)
    } finally {
      setLoadingWaf(false)
    }
  }

  useEffect(() => {
    if (activeNav === 'waf' || activeNav === 'home') loadWafResponse()
  }, [activeNav])

  useEffect(() => {
    setExpandedPolicyCard('')
  }, [selectedLocation])

  const loadDevices = async () => {
    setLoadingDevices(true)
    setDeviceError('')
    try {
      const res = await fetch(`${API_BASE}/devices`)
      if (!res.ok) throw new Error('Failed to load devices')
      const data = await res.json()
      setDevices(data)
    } catch (err) {
      setDeviceError(err.message)
    } finally {
      setLoadingDevices(false)
    }
  }

  useEffect(() => {
    if (activeNav === 'device-config') loadDevices()
  }, [activeNav])

  useEffect(() => {
    if (activeNav === 'waf' && devices.length === 0) loadDevices()
  }, [activeNav, devices.length])

  const submitSearch = (event) => {
    event.preventDefault()
    if (!prompt.trim()) {
      setSearchResult('Please enter a search term.')
      return
    }

    const normalized = wafText.toLowerCase()
    const term = prompt.toLowerCase()
    const count = normalized.split(term).length - 1

    if (count > 0) {
      setSearchResult(`Found ${count} matches in the latest WAF response.`)
    } else {
      setSearchResult('No matches found in the latest WAF response.')
    }
  }

  const openPlatformSettings = () => {
    const nextExpandedState = !settingsExpanded
    setSettingsExpanded(nextExpandedState)
    if (nextExpandedState) {
      setActiveNav('device-config')
    } else if (activeNav === 'device-config') {
      setActiveNav('home')
    }
    setSettingsGearSpinning(true)
    window.setTimeout(() => setSettingsGearSpinning(false), 650)
  }

  const updateNewDeviceField = (field, value) => {
    setNewDevice((prev) => ({ ...prev, [field]: value }))
  }

  const saveNewDevice = async () => {
    setDeviceError('')
    try {
      if (!newDevice.apikey.trim()) {
        throw new Error('APIKEY cannot be Empty')
      }
      const res = await fetch(`${API_BASE}/devices`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Role': 'admin' },
        body: JSON.stringify({
          name: newDevice.name,
          ip: newDevice.ip,
          model: newDevice.model,
          environment: newDevice.environment,
          region: newDevice.region,
          firmware: newDevice.firmware,
          apikey: newDevice.apikey,
          status: 'Online',
          last_sync: 'Just now'
        })
      })
      if (!res.ok) throw new Error('Failed to save device')
      const created = await res.json()
      setDevices((prev) => [created, ...prev])
      setAddDeviceModalOpen(false)
    } catch (err) {
      setDeviceError(err.message)
    }
  }

  const viewDevice = async (deviceId) => {
    setDeviceError('')
    try {
      const res = await fetch(`${API_BASE}/devices/${deviceId}`)
      if (!res.ok) throw new Error('Failed to load device details')
      const device = await res.json()
      setViewedDevice(device)
    } catch (err) {
      setDeviceError(err.message)
    }
  }

  const deleteDevice = async (deviceId) => {
    setDeviceError('')
    try {
      const res = await fetch(`${API_BASE}/devices/${deviceId}`, {
        method: 'DELETE',
        headers: { 'X-Role': 'admin' }
      })
      if (!res.ok) throw new Error('Failed to delete device')
      setDevices((prev) => prev.filter((device) => device.id !== deviceId))
      if (viewedDevice?.id === deviceId) setViewedDevice(null)
    } catch (err) {
      setDeviceError(err.message)
    }
  }

  const getPolicyStatus = (policy) => {
    const ip = typeof policy === 'string' ? '' : (policy.ip || '').trim()
    if (!ip) return { label: 'Not Protected', className: 'not-protected' }
    const monitorMode = typeof policy === 'string' ? '' : String(policy['monitor-mode'] ?? policy.monitor_mode ?? '').toLowerCase()
    if (monitorMode === 'enable') return { label: 'Monitoring', className: 'monitoring' }
    return { label: 'Blocking', className: 'blocking' }
  }

  const getPolicyTabId = (policy) => {
    const policyName = policy?.server_policy_name || 'Policy Details'
    const deviceName = policy?._deviceName || 'Unknown Device'
    const policyIp = policy?.ip || 'no-ip'
    return `${deviceName}::${policyName}::${policyIp}`
  }

  const openPolicyTab = (policy, index) => {
    const policyName = policy?.server_policy_name || `Policy ${index + 1}`
    const tabId = getPolicyTabId(policy)

    setWafTabs((prev) => {
      if (prev.some((tab) => tab.id === tabId)) return prev
      return [...prev, { id: tabId, title: policyName, type: 'policy', policy }]
    })
    setActiveWafTabId(tabId)
  }

  const closeWafTab = (tabId) => {
    if (tabId === MAIN_WAF_TAB_ID) return
    setWafTabs((prev) => {
      const next = prev.filter((tab) => tab.id !== tabId)
      if (activeWafTabId === tabId) {
        const closedIndex = prev.findIndex((tab) => tab.id === tabId)
        const fallback = next[Math.max(0, closedIndex - 1)] || next[0] || { id: MAIN_WAF_TAB_ID }
        setActiveWafTabId(fallback.id)
      }
      return next
    })
  }

  const activeWafTab = wafTabs.find((tab) => tab.id === activeWafTabId) || wafTabs[0]

  return (
    <div className={`dashboard-page ${darkMode ? 'dark' : 'light'}`}>
      <div className="ambient-layer" />
      <div className={`dashboard-shell ${sidebarOpen ? 'sidebar-open' : 'sidebar-closed'}`}>
        <aside className={`sidebar ${sidebarOpen ? 'is-open' : 'is-closed'}`}>
          <div className="sidebar-top">
            <button onClick={() => setActiveNav('home')} className="home-link">
              <div className="brand-logo-shell">
                <SecurityPerspectiveLogo />
              </div>
              <div>
                <div className="kicker">Security Platform</div>
                <div className="brand-title sidebar-title">
                  <span>Security</span> <span className="gradient-text">Perspective</span>
                </div>
              </div>
            </button>
            <nav className="nav-list">
              {navItems.map((item) => {
                const active = activeNav === item.id
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => {
                      setActiveNav(item.id)
                    }}
                    className={`nav-item ${active ? 'active' : ''}`}
                  >
                    <div>
                      <div className="nav-title">{item.label}</div>
                      <div className="nav-desc">{item.description}</div>
                    </div>
                    <span className="status-dot" />
                  </button>
                )
              })}
            </nav>
          </div>

          <div className={`settings-box ${settingsExpanded ? 'expanded' : ''}`}>
            <button type="button" className={`settings-btn ${settingsGearSpinning ? 'spinning' : ''}`} onClick={openPlatformSettings}>
              <span className="settings-gear" aria-hidden="true">⚙</span> Platform Settings
            </button>
            {settingsExpanded && (
              <button type="button" className={`settings-subitem ${activeNav === 'device-config' ? 'active' : ''}`} onClick={() => setActiveNav('device-config')}>
                Device Config
              </button>
            )}
          </div>
        </aside>

        <main className="main-panel">
          <header className="topbar">
            <div>
              <button type="button" onClick={() => setSidebarOpen((prev) => !prev)} className="sidebar-icon-btn" aria-label={sidebarOpen ? 'Close sidebar' : 'Open sidebar'}>
                <span className="sidebar-icon" aria-hidden="true">◧</span>
                <span className="sidebar-tooltip">{sidebarOpen ? 'Close sidebar' : 'Open sidebar'}</span>
              </button>
              <div className="kicker">Workspace</div>
              <h1 className="workspace-title">
                {activeNav === 'home'
                  ? 'Search'
                  : activeNav === 'waf'
                    ? 'WAF Configuration'
                    : activeNav === 'automation'
                      ? 'Automation'
                    : activeNav === 'device-config'
                      ? 'Device Config'
                      : 'Executive Overview'}
              </h1>
              {activeNav === 'waf' && <p className="waf-updated">Last updated: {new Date().toLocaleString()}</p>}
            </div>

            <div className="topbar-right">
              <button type="button" onClick={onToggleTheme} className="theme-btn">
                {darkMode ? 'Light' : 'Dark'}
              </button>

              <div className="profile-menu" ref={menuRef}>
                <button type="button" onClick={() => setMenuOpen((prev) => !prev)} className="avatar-btn">
                  {username.slice(0, 2).toUpperCase()}
                </button>

                {menuOpen && (
                  <div className="menu-popover">
                    <div className="user-card">
                      <div className="nav-title">{username}</div>
                      <div className="nav-desc">Cyber Security Lead</div>
                    </div>
                    <button type="button" className="menu-action">Help</button>
                    <button type="button" className="menu-action" onClick={onLogout}>Logout</button>
                  </div>
                )}
              </div>
            </div>
          </header>

          <section className={`body-content ${activeNav === 'home' ? 'home-centered' : ''}`}>
            {activeNav === 'home' && (
              <form className="search-wrap" onSubmit={submitSearch}>
                <div className="hero-text">How can I help you? :)</div>
                <div className="search-bar">
                  <div className="search-input-with-icon">
                    <span className="search-icon" aria-hidden="true">⌕</span>
                    <input type="text" value={prompt} onChange={(e) => setPrompt(e.target.value)} placeholder="Search..." />
                  </div>
                  <button type="submit">Search</button>
                </div>
                {searchResult && <p className="search-result">{searchResult}</p>}
              </form>
            )}

            {activeNav === 'waf' && (
              <section className="waf-panel modern-waf">
                <div className="workspace-tab-bar" role="tablist" aria-label="WAF workspace tabs">
                  {wafTabs.map((tab) => (
                    <button
                      key={tab.id}
                      type="button"
                      role="tab"
                      aria-selected={activeWafTabId === tab.id}
                      className={`workspace-tab ${activeWafTabId === tab.id ? 'active' : ''}`}
                      onClick={() => setActiveWafTabId(tab.id)}
                    >
                      <span className="workspace-tab-label">{tab.title}</span>
                      {tab.id !== MAIN_WAF_TAB_ID && (
                        <span
                          className="workspace-tab-close"
                          role="button"
                          aria-label={`Close ${tab.title}`}
                          onClick={(event) => {
                            event.stopPropagation()
                            closeWafTab(tab.id)
                          }}
                        >
                          ×
                        </span>
                      )}
                    </button>
                  ))}
                </div>

                {activeWafTab?.type === 'main' ? (
                  <>
                    <div className="waf-search-shell">
                      <div className="waf-policy-search">
                        <div className="search-input-with-icon">
                          <span className="search-icon" aria-hidden="true">⌕</span>
                          <input
                            type="text"
                            value={wafSearch}
                            onChange={(e) => setWafSearch(e.target.value)}
                            placeholder="Search by policy name, IP, or hostname"
                            aria-label="Search WAF policies"
                          />
                        </div>
                      </div>
                      <div className="waf-location-card">
                        <span className="waf-location-label">Location</span>
                        <select value={selectedLocation} onChange={(e) => setSelectedLocation(e.target.value)} aria-label="Filter by location">
                          {locationOptions.map((location) => (
                            <option key={location} value={location}>{location}</option>
                          ))}
                        </select>
                      </div>
                      <button type="button" className="theme-btn" onClick={loadWafResponse} disabled={loadingWaf}>Refresh</button>
                    </div>
                    {loadingWaf && <p className="nav-desc">Loading...</p>}
                    {wafError && <p className="error-box">{wafError}</p>}
                    {!loadingWaf && !wafError && (
                      <>
                        {wafPolicies.length === 0 ? (
                          <div className="waf-empty-state">
                            <p className="nav-desc">No devices or server policies found.</p>
                          </div>
                        ) : filteredWafPolicies.length === 0 ? (
                          <div className="waf-empty-state">
                            <p className="nav-desc">No matches found for "{wafSearch}".</p>
                          </div>
                        ) : (
                          <div className="waf-card-grid">
                            {filteredWafPolicies.map((policy, index) => {
                              const { label: policyStatusLabel, className: policyStatusClass } = getPolicyStatus(policy)
                              const policyName = typeof policy === 'string' ? policy : policy.server_policy_name
                              const policyIp = typeof policy === 'string' ? '' : policy.ip
                              const tlsV10 = typeof policy === 'string' ? null : policy.tls_v10
                              const tlsV11 = typeof policy === 'string' ? null : policy.tls_v11
                              const tlsV12 = typeof policy === 'string' ? null : policy.tls_v12
                              const tlsV13 = typeof policy === 'string' ? null : policy.tls_v13
                              const http2 = typeof policy === 'string' ? null : policy.http2
                              const trafficMirror = typeof policy === 'string' ? '' : (policy['traffic-mirror'] ?? policy.traffic_mirror ?? '')
                              const sni = typeof policy === 'string' ? '' : policy.sni
                              const allowHostsEntries = typeof policy === 'string' ? [] : (policy.allow_hosts_entries || [])
                              const hostname = allowHostsEntries[0]?.host || ''
                              const clientCertificateDetails = typeof policy === 'string' ? {} : (policy.client_certificate_details || {})
                              const certificateCn = clientCertificateDetails.cn || clientCertificateDetails.subject || '-'
                              const certificateIssuer = clientCertificateDetails.issuer || '-'
                              const certificateExpireDate = clientCertificateDetails.expire_date || clientCertificateDetails.valid_to || '-'
                              const certificateDaysLeft = clientCertificateDetails.days_left ?? '-'
                              const tlsV10V11 = [tlsV10, tlsV11].map((value) => (value === null ? '-' : String(value))).join(' / ')
                              const { Icon: CardPolicyStatusIcon, toneClass: policyStatusTone } = getPolicyStatusVisual(policyStatusLabel)
                              return (
                              <article
                                className={`policy-card ${expandedPolicyCard === `${policyName}-${index}` ? 'selected' : ''}`}
                                key={typeof policy === 'string' ? `policy-${index}` : getPolicyTabId(policy)}
                                onClick={() => setExpandedPolicyCard((prev) => (prev === `${policyName}-${index}` ? '' : `${policyName}-${index}`))}
                              >
                                <div className="policy-top-row">
                                  <div>
                                    <p className="policy-label">Server Policy</p>
                                    <p className="policy-name">{policyName}</p>
                                    <div className="policy-device-row">
                                      <span className="policy-device-icon" aria-hidden="true">
                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                          <rect width="20" height="8" x="2" y="2" rx="2" ry="2" />
                                          <rect width="20" height="8" x="2" y="14" rx="2" ry="2" />
                                          <line x1="6" x2="6.01" y1="6" y2="6" />
                                          <line x1="6" x2="6.01" y1="18" y2="18" />
                                        </svg>
                                      </span>
                                      <span className="policy-device-label">Device</span>
                                      <strong>{policy._deviceName || '-'}</strong>
                                    </div>
                                  </div>
                                  <div className="policy-status-wrap">
                                    <span className={`policy-status-pill ${policyStatusClass} status-pill-modern ${policyStatusTone}`}>
                                      <span className="policy-status-dot" aria-hidden="true" />
                                      <CardPolicyStatusIcon className="policy-status-icon" />
                                      <span className="policy-status-text">{policyStatusLabel}</span>
                                    </span>
                                    <span className={`policy-expand-icon ${expandedPolicyCard === `${policyName}-${index}` ? 'expanded' : ''}`} aria-hidden="true">
                                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                                        <path d="m6 9 6 6 6-6" />
                                      </svg>
                                    </span>
                                  </div>
                                </div>
                                {expandedPolicyCard === `${policyName}-${index}` && (
                                  <section className="policy-summary" aria-label="Quick configuration summary">
                                    <div className="policy-summary-head">
                                      <div>
                                        <h4>Quick configuration summary</h4>
                                        <p className="policy-summary-subtitle">Review endpoint, certificate, and network posture before opening the full page.</p>
                                      </div>
                                      <button
                                        type="button"
                                        className="policy-full-details-btn"
                                        onClick={(event) => {
                                          event.stopPropagation()
                                          if (typeof policy === 'string') return
                                          openPolicyTab(policy, index)
                                        }}
                                      >
                                        <span>Full Details</span>
                                        <svg
                                          className="policy-full-details-icon"
                                          viewBox="0 0 24 24"
                                          fill="none"
                                          xmlns="http://www.w3.org/2000/svg"
                                          aria-hidden="true"
                                        >
                                          <path d="M7 7h10v10" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                                          <path d="M7 17 17 7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                                        </svg>
                                      </button>
                                    </div>
                                    <div className="policy-summary-grid">
                                      <article className="policy-summary-section">
                                        <h5>Endpoint <span aria-hidden="true">✣</span></h5>
                                        <p><span>IP</span><strong>{policyIp || '-'}</strong></p>
                                        <p><span>SNI</span><strong>{sni || '-'}</strong></p>
                                        <p><span>Hostname</span><strong>{hostname || '-'}</strong></p>
                                        <p><span>Traffic Mirror</span><strong>{trafficMirror || '-'}</strong></p>
                                      </article>
                                      <article className="policy-summary-section">
                                        <h5>Certificate <span aria-hidden="true">✣</span></h5>
                                        <p><span>CN</span><strong>{certificateCn}</strong></p>
                                        <p><span>Issuer</span><strong>{certificateIssuer}</strong></p>
                                        <p><span>Expire Date</span><strong>{certificateExpireDate}</strong></p>
                                        <p><span>Days Left</span><strong>{certificateDaysLeft}</strong></p>
                                      </article>
                                      <article className="policy-summary-section">
                                        <h5>Network <span aria-hidden="true">✣</span></h5>
                                        <p><span>TLSv1.3</span><strong>{tlsV13 === null ? '-' : String(tlsV13)}</strong></p>
                                        <p><span>TLSv1.2</span><strong>{tlsV12 === null ? '-' : String(tlsV12)}</strong></p>
                                        <p><span>TLSv1.0-1.1</span><strong>{tlsV10V11}</strong></p>
                                        <p><span>HTTP/2</span><strong>{http2 === null ? '-' : String(http2)}</strong></p>
                                      </article>
                                    </div>
                                  </section>
                                )}
                              </article>
                              )
                            })}
                          </div>
                        )}
                      </>
                    )}
                  </>
                ) : (
                  <FullDetailsPage policy={activeWafTab?.policy} />
                )}
              </section>
            )}

            {activeNav === 'automation' && (
              <section className="waf-panel modern-waf">
                <div className="waf-card-grid">
                  {[
                    {
                      id: 'server-policy-disable',
                      title: 'Server Policy Disable',
                      definition: 'Disables configured server policy enforcement and bypasses the policy chain for matching traffic.'
                    },
                    {
                      id: 'recaptcha-disable',
                      title: 'Recaptcha Disable',
                      definition: 'Turns off CAPTCHA challenge checks, allowing requests to pass without Recaptcha validation.'
                    }
                  ].map((card) => (
                    <article
                      key={card.id}
                      className={`policy-card ${expandedAutomationCard === card.id ? 'selected' : ''}`}
                      onClick={() => setExpandedAutomationCard((prev) => (prev === card.id ? '' : card.id))}
                    >
                      <div className="policy-top-row">
                        <div>
                          <p className="policy-label">Automation</p>
                          <p className="policy-name">{card.title}</p>
                        </div>
                        <div className="policy-status-wrap">
                          <span className={`policy-expand-icon ${expandedAutomationCard === card.id ? 'expanded' : ''}`} aria-hidden="true">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                              <path d="m6 9 6 6 6-6" />
                            </svg>
                          </span>
                        </div>
                      </div>
                      {expandedAutomationCard === card.id && (
                        <section className="policy-summary automation-definition" aria-label={`${card.title} definition`}>
                          <div className="policy-summary-head">
                            <h4>Definition</h4>
                          </div>
                          <p>{card.definition}</p>
                        </section>
                      )}
                    </article>
                  ))}
                </div>
              </section>
            )}

            {activeNav === 'overview' && <div className="hero-text muted">This page will be designed next.</div>}
            {activeNav === 'device-config' && (
              <section className="device-page">
                <div className="device-topbar">
                  <div>
                    <span className="device-kicker">● Device Management</span>
                    <h2 className="device-title">Manage FortiWeb Devices</h2>
                    <p className="device-subtitle">Add, review, filter, and remove devices connected to your WAF configuration platform.</p>
                  </div>
                  <div className="device-topbar-actions">
                    <button type="button" className="add-device-btn" onClick={() => setAddDeviceModalOpen(true)}>+ Add Device</button>
                    <button type="button" className="add-device-btn" onClick={collectWafResponse} disabled={loadingWaf}>{loadingWaf ? 'Collecting...' : 'Collect From WAF'}</button>
                  </div>
                </div>

                <div className="device-stats-grid">
                  <article className="device-stat-card"><p>Total Devices</p><h3>{deviceStats.total}</h3><span>Across all environments</span></article>
                  <article className="device-stat-card"><p>Online</p><h3>{deviceStats.online}</h3><span>Healthy and reachable</span></article>
                  <article className="device-stat-card"><p>Warning</p><h3>{deviceStats.warning}</h3><span>Needs attention</span></article>
                  <article className="device-stat-card"><p>Offline</p><h3>{deviceStats.offline}</h3><span>No recent sync</span></article>
                </div>

                <div className="device-filter-row">
                  <input type="text" placeholder="Search by device name, IP, or region" value={deviceSearch} onChange={(e) => setDeviceSearch(e.target.value)} />
                  <select value={deviceStatusFilter} onChange={(e) => setDeviceStatusFilter(e.target.value)}>
                    <option>All</option>
                    <option>Online</option>
                    <option>Warning</option>
                    <option>Offline</option>
                  </select>
                </div>

                <div className="device-list">
                  {loadingDevices && <p className="nav-desc">Loading devices...</p>}
                  {deviceError && <p className="error-box">{deviceError}</p>}
                  {filteredDevices.map((device) => (
                    <article className="device-card" key={device.id}>
                      <div>
                        <h3 className="device-card-name">{device.name} <span className={`status-pill ${device.status.toLowerCase()}`}>{device.status}</span></h3>
                        <div className="device-card-meta">{device.ip}</div>
                        <div className="device-card-meta">{device.model} · v{device.firmware}</div>
                      </div>
                      <div><p className="device-label">Environment</p><strong>{device.environment}</strong></div>
                      <div><p className="device-label">Region</p><strong>{device.region}</strong></div>
                      <div><p className="device-label">Last Sync</p><strong>{device.last_sync}</strong></div>
                      <div className="device-actions"><button type="button" onClick={() => viewDevice(device.id)}>View</button><button type="button" className="danger" onClick={() => deleteDevice(device.id)}>Delete</button></div>
                    </article>
                  ))}
                </div>

                {addDeviceModalOpen && (
                  <div className="device-modal-overlay" role="dialog" aria-modal="true">
                    <div className="device-modal">
                      <div className="device-modal-head">
                        <div>
                          <h3>Add Device</h3>
                          <p>Register a new FortiWeb device for API sync and configuration tracking.</p>
                        </div>
                        <button type="button" className="device-modal-close" onClick={() => setAddDeviceModalOpen(false)}>×</button>
                      </div>

                      <div className="device-modal-grid">
                        <label>Device Name<input value={newDevice.name} onChange={(e) => updateNewDeviceField('name', e.target.value)} /></label>
                        <label>Management IP<input value={newDevice.ip} onChange={(e) => updateNewDeviceField('ip', e.target.value)} /></label>
                        <label>Environment<select value={newDevice.environment} onChange={(e) => updateNewDeviceField('environment', e.target.value)}><option>Production</option><option>Disaster Recovery</option><option>Test</option></select></label>
                        <label>Region<input value={newDevice.region} onChange={(e) => updateNewDeviceField('region', e.target.value)} /></label>
                        <label>Model<select value={newDevice.model} onChange={(e) => updateNewDeviceField('model', e.target.value)}><option>FortiWeb VM</option><option>FortiWeb 4000E</option></select></label>
                        <label>Firmware Version<input value={newDevice.firmware} onChange={(e) => updateNewDeviceField('firmware', e.target.value)} /></label>
                        <label>APIKEY<input value={newDevice.apikey} onChange={(e) => updateNewDeviceField('apikey', e.target.value)} /></label>
                      </div>
                      <div className="device-modal-actions">
                        <button type="button" onClick={() => setAddDeviceModalOpen(false)}>Cancel</button>
                        <button type="button" className="primary" onClick={saveNewDevice}>Save Device</button>
                      </div>
                    </div>
                  </div>
                )}

                {viewedDevice && (
                  <div className="device-modal-overlay" role="dialog" aria-modal="true">
                    <div className="device-modal">
                      <div className="device-modal-head">
                        <div>
                          <h3>{viewedDevice.name}</h3>
                          <p>Device details from database record.</p>
                        </div>
                        <button type="button" className="device-modal-close" onClick={() => setViewedDevice(null)}>×</button>
                      </div>
                      <div className="device-modal-grid">
                        <label>Management IP<input value={viewedDevice.ip} readOnly /></label>
                        <label>Status<input value={viewedDevice.status} readOnly /></label>
                        <label>Environment<input value={viewedDevice.environment} readOnly /></label>
                        <label>Region<input value={viewedDevice.region} readOnly /></label>
                        <label>Model<input value={viewedDevice.model} readOnly /></label>
                        <label>Firmware<input value={viewedDevice.firmware} readOnly /></label>
                      </div>
                    </div>
                  </div>
                )}
              </section>
            )}
          </section>
        </main>
      </div>
    </div>
  )
}

export default function App() {
  const [darkMode, setDarkMode] = useState(() => {
    const storedTheme = localStorage.getItem('sp_theme')
    if (storedTheme === 'dark') return true
    if (storedTheme === 'light') return false
    return window.matchMedia('(prefers-color-scheme: dark)').matches
  })

  const [session, setSession] = useState(() => {
    const raw = localStorage.getItem('sp_session')
    return raw ? JSON.parse(raw) : null
  })

  useEffect(() => {
    localStorage.setItem('sp_theme', darkMode ? 'dark' : 'light')
  }, [darkMode])

  const toggleTheme = () => {
    setDarkMode((prev) => !prev)
  }

  const handleLogin = (data) => {
    localStorage.setItem('sp_session', JSON.stringify(data))
    setSession(data)
  }

  const handleLogout = () => {
    localStorage.removeItem('sp_session')
    setSession(null)
  }

  return session
    ? <AppShell session={session} onLogout={handleLogout} darkMode={darkMode} onToggleTheme={toggleTheme} />
    : <LoginCard onLogin={handleLogin} darkMode={darkMode} onToggleTheme={toggleTheme} />
}
