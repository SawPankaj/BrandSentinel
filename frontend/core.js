/* Deterministic, source-grounded demo checks. No model or network calls. */
(function(root){
  function runChecks(text, knowledge=[], sourceChecks=[]){
    const findings=[];
    const add=(kind,severity,confidence,quote,reason,source,suggestion,method='Rule-based')=>findings.push({id:'f'+Math.random().toString(36).slice(2,8),kind,severity,confidence,quote,reason,source,suggestion,status:'Open',method});
    const absolute=text.match(/\b(guarantee(?:s|d)?|100%|risk-free|no risk|always|never)\b[^.!?]*/i);
    if(absolute)add('Unsupported claim','High',97,absolute[0].trim(),'Absolute outcome language needs an approved claim and supporting evidence. No matching approved claim is available in this demo knowledge base.','Claims library · No approved claim found','Replace with a precise, evidence-backed statement; ask the authorised reviewer if the claim is essential.');
    const configuredTerms=[];
    for(const rule of knowledge.filter(r=>r.category==='Terminology'&&r.bannedTerm&&r.preferredTerm)){
      const escaped=rule.bannedTerm.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
      const re=new RegExp(`\\b${escaped}\\b`,'gi');
      for(const match of text.matchAll(re)){configuredTerms.push(match.index);add('Terminology','Medium',96,match[0],`The approved terminology entry prefers “${rule.preferredTerm}”.`,`${rule.source||'Brand knowledge'} · ${rule.title}`,rule.preferredTerm)}
    }
    const hasStudentsRule=knowledge.some(r=>r.category==='Terminology'&&r.bannedTerm?.toLowerCase()==='students');
    if(!hasStudentsRule){for(const m of text.matchAll(/\bstudents\b/gi))if(!configuredTerms.includes(m.index))add('Terminology','Medium',96,m[0],'The Northstar glossary prefers “learners” for people enrolled in a programme.','Brand guideline · Terminology rule 01 · version 2.4','learners')}
    const link=text.match(/\b(click here|learn more here)\b/i);
    if(link)add('Accessibility','Low',99,link[0],'This link text does not describe its destination for screen-reader users.','Accessibility rule pack · Descriptive link text','Use descriptive link text, such as “Explore the programme”.');
    const hype=text.match(/\b(achieve your dreams|best in the world|revolutionary|once-in-a-lifetime)\b/i);
    if(hype)add('Tone of voice','Low',88,hype[0],'This phrase may sound promotional rather than clear, practical and encouraging.','Brand guideline · Voice principles · version 2.4','Describe the practical benefit in plain language.','Rule-based');
    const facts=knowledge.filter(r=>['Approved facts','Claims'].includes(r.category)).map(r=>r.detail.toLowerCase()).join(' ');
    const quantities=[...text.matchAll(/\b\d+(?:\.\d+)?\s?(?:%|percent|times?|x|weeks?|months?|years?)\b/gi)];
    for(const match of quantities){if(facts.includes(match[0].toLowerCase())||findings.some(f=>f.kind==='Unsupported claim'&&f.quote.includes(match[0])))continue;const start=text.lastIndexOf('.',match.index)+1,end=text.indexOf('.',match.index);const quote=text.slice(Math.max(0,start),end<0?text.length:end).trim();add('Unverified fact','Medium',92,quote||match[0],'This measurable statement does not match an approved fact or claim in the knowledge base. A person should confirm the source before publication.','Approved facts register · No matching entry','Add the approved source or revise the statement to a verifiable fact.')}
    for(const check of sourceChecks){if(findings.some(f=>f.kind===check.kind&&f.quote===check.quote))continue;findings.push({...check,id:'f'+Math.random().toString(36).slice(2,8),method:'Rule-based',status:'Open'})}
    return findings;
  }
  function canApprove(findings){return findings.every(f=>f.status!=='Open'&&f.status!=='Escalated'&&(!['Unsupported claim','Unverified fact'].includes(f.kind)||f.status==='Reviewer cleared'));}
  function recheck(existing,text,knowledge=[],sourceChecks=[]){const all=existing.slice();for(const fresh of runChecks(text,knowledge,sourceChecks)){const duplicate=all.some(old=>old.status==='Open'&&old.kind===fresh.kind&&old.quote===fresh.quote);if(!duplicate)all.push(fresh)}return all;}
  root.BrandSentinelCore={runChecks,canApprove,recheck};
  if(typeof module!=='undefined'&&module.exports)module.exports={runChecks,canApprove,recheck};
})(typeof window!=='undefined'?window:globalThis);
