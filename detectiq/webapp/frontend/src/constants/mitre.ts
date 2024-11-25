export interface MITRETactic {
  id: string;
  name: string;
}

export const MITRE_TACTICS: MITRETactic[] = [
  { id: 'initial_access', name: 'Initial Access' },
  { id: 'execution', name: 'Execution' },
  { id: 'persistence', name: 'Persistence' },
  { id: 'privilege_escalation', name: 'Privilege Escalation' },
  { id: 'defense_evasion', name: 'Defense Evasion' },
  { id: 'credential_access', name: 'Credential Access' },
  { id: 'discovery', name: 'Discovery' },
  { id: 'lateral_movement', name: 'Lateral Movement' },
  { id: 'collection', name: 'Collection' },
  { id: 'command_and_control', name: 'Command and Control' },
  { id: 'exfiltration', name: 'Exfiltration' },
  { id: 'impact', name: 'Impact' },
]; 