(function(root,factory){
  const api=factory();
  if(typeof module==="object"&&module.exports)module.exports=api;
  if(root)root.RepoShieldScanner=api;
})(typeof window!=="undefined"?window:(typeof globalThis!=="undefined"?globalThis:this),function(){
  "use strict";

  function isPlaceholder(value){
    const v=String(value||"").trim().toLowerCase();
    if(!v)return true;
    return /^(?:your(?:[-_\s]|$)|replace(?:[-_\s]|$)|insert(?:[-_\s]|$)|example(?:[-_\s]|$)|sample(?:[-_\s]|$)|dummy(?:[-_\s]|$)|fake(?:[-_\s]|$)|change(?:me|it)(?:[-_\s]|$)|redacted(?:[-_\s]|$)|placeholder(?:[-_\s]|$)|x{4,}(?:[-_\s]|$)|<|\$|process\.env\b|os\.(?:getenv|environ)\b|(?:none|null|undefined)$)/i.test(v)
      || /^test(?:[-_\s](?:value|password|key|token|secret|credential)|$)/i.test(v);
  }

  function tokenIsPlaceholder(value){
    const suffix=String(value||"").replace(/^(?:ghp_|github_pat_|xox[bp]-|AIza|AKIA)/i,"");
    return isPlaceholder(suffix)||/(?:example|placeholder|dummy|fake|redacted|your(?:token|key|secret)|x{5,})/i.test(suffix);
  }

  function redactEvidence(line){
    return String(line)
      .replace(/(?:ghp_|github_pat_)[A-Za-z0-9_]{8,}/g,"[REDACTED]")
      .replace(/glpat-[A-Za-z0-9_-]{20,}/g,"[REDACTED]")
      .replace(/npm_[A-Za-z0-9]{30,}/g,"[REDACTED]")
      .replace(/sk_live_[A-Za-z0-9]{16,}/g,"[REDACTED]")
      .replace(/sk-(?:proj-)?[A-Za-z0-9_-]{20,}/g,"[REDACTED]")
      .replace(/xox[bp]-[A-Za-z0-9-]{8,}/g,"[REDACTED]")
      .replace(/AIza[A-Za-z0-9_-]{20,}/g,"[REDACTED]")
      .replace(/\bAKIA[A-Z0-9]{16}\b/g,"[REDACTED]")
      .replace(/(\b[\w.-]*(?:password|passwd|client_secret|api_key|secret_key|access_token|aws_secret_access_key|aws_session_token|stripe_secret_key|private_key)\b\s*[:=]\s*["']?)[^"'\s,;#}\]]+/ig,"$1[REDACTED]")
      .replace(/(\bBearer\s+)[A-Za-z0-9._~-]{20,}/ig,"$1[REDACTED]")
      .slice(0,180);
  }

  function sourceUrl(owner,repo,branch,path,line){
    const branchPath=String(branch||"main").split("/").map(encodeURIComponent).join("/");
    const filePath=String(path||"").split("/").map(encodeURIComponent).join("/");
    return "https://github.com/"+owner+"/"+repo+"/blob/"+branchPath+"/"+filePath+"#L"+line;
  }

  function scanText(text,path,owner,repo,branch,findings){
    const output=findings||[];
    const lines=String(text).split(/\r?\n/);
    lines.forEach((line,index)=>{
      let title="",severity="high",category="Secret";
      const privateKey=line.match(/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/i);
      const githubToken=line.match(/(?:ghp_|github_pat_)[A-Za-z0-9_]{8,}/);
      const gitlabToken=line.match(/glpat-[A-Za-z0-9_-]{20,}/);
      const npmToken=line.match(/npm_[A-Za-z0-9]{30,}/);
      const stripeToken=line.match(/sk_live_[A-Za-z0-9]{16,}/);
      const openAIToken=line.match(/sk-(?:proj-)?[A-Za-z0-9_-]{20,}/);
      const slackToken=line.match(/xox[bp]-[A-Za-z0-9-]{8,}/);
      const googleToken=line.match(/AIza[A-Za-z0-9_-]{20,}/);
      const awsKey=line.match(/\bAKIA[A-Z0-9]{16}\b/);
      const bearerToken=line.match(/\bBearer\s+([A-Za-z0-9._~-]{20,})/i);
      const genericAssignment=line.match(/\b[\w.-]*(?:password|passwd|client_secret|api_key|secret_key|access_token|aws_secret_access_key|aws_session_token|stripe_secret_key|private_key)\s*[:=]\s*["']?([^"'\s,;#}\]]+)/i);
      if(privateKey){title="Private key material";severity="critical";}
      else if(githubToken&&!tokenIsPlaceholder(githubToken[0]))title="Possible GitHub credential";
      else if(gitlabToken&&!tokenIsPlaceholder(gitlabToken[0]))title="Possible GitLab credential";
      else if(npmToken&&!tokenIsPlaceholder(npmToken[0]))title="Possible npm token";
      else if(stripeToken&&!tokenIsPlaceholder(stripeToken[0]))title="Possible Stripe secret key";
      else if(openAIToken&&!tokenIsPlaceholder(openAIToken[0]))title="Possible OpenAI API key";
      else if(slackToken&&!tokenIsPlaceholder(slackToken[0]))title="Possible Slack credential";
      else if(googleToken&&!tokenIsPlaceholder(googleToken[0]))title="Possible Google API key";
      else if(awsKey&&!tokenIsPlaceholder(awsKey[0]))title="Possible cloud access key";
      else if(bearerToken&&!tokenIsPlaceholder(bearerToken[1]))title="Possible hard-coded bearer token";
      else if(genericAssignment&&line.length>25&&!isPlaceholder(genericAssignment[1]))title="Possible hard-coded credential";
      if(title){
        output.push({
          severity,category,title,
          description:"This line resembles a credential pattern. It may be a false positive; verify whether the value is real.",
          file:path,line:index+1,evidence:redactEvidence(line),
          remediation:"If real, revoke or rotate the credential, remove it from source, and consider cleaning Git history.",
          source_url:sourceUrl(owner,repo,branch,path,index+1)
        });
      }
      if(String(path).startsWith(".github/workflows/")&&line.toLowerCase().includes("write-all")){
        output.push({severity:"high",category:"Workflow",title:"Broad workflow permissions",description:"Broad write permissions increase the impact of a compromised workflow step.",file:path,line:index+1,evidence:redactEvidence(line),remediation:"Use least-privilege permissions at workflow or job scope.",source_url:sourceUrl(owner,repo,branch,path,index+1)});
      }
      if(String(path).startsWith(".github/workflows/")&&/@main\b/.test(line)){
        output.push({severity:"medium",category:"Workflow",title:"Action uses a moving branch reference",description:"A branch reference can change without a reviewed workflow update.",file:path,line:index+1,evidence:redactEvidence(line),remediation:"Pin third-party actions to a full commit SHA.",source_url:sourceUrl(owner,repo,branch,path,index+1)});
      }
      if(!/\.(?:md|txt)$/i.test(String(path))){
        let risk="",riskSeverity="medium";
        if(/(?:curl|wget)\b[^|]{0,240}\|\s*(?:sh|bash|zsh)\b/i.test(line)){risk="Remote script piped directly to a shell";riskSeverity="high";}
        else if(/powershell(?:\.exe)?\b.{0,100}-(?:enc|encodedcommand)\b/i.test(line)){risk="PowerShell encoded command";riskSeverity="high";}
        else if(/\beval\s*\(\s*(?:atob|Buffer\.from)\s*\(/i.test(line)){risk="Dynamic execution of encoded content";riskSeverity="high";}
        else if(/(?:execSync|spawn|child_process)\s*\([^)]{0,180}(?:https?:\/\/|curl\b|wget\b)/i.test(line)){risk="Process execution combined with remote content";riskSeverity="medium";}
        if(risk){
          output.push({severity:riskSeverity,category:"Suspicious code",title:risk,description:"This pattern can be used for unsafe remote-code execution or obfuscation. Inspect surrounding code and confirm its purpose.",file:path,line:index+1,evidence:redactEvidence(line),remediation:"Avoid piping remote scripts directly to shells. Verify downloads, pin trusted sources, and remove unnecessary dynamic execution.",source_url:sourceUrl(owner,repo,branch,path,index+1)});
        }
      }
    });
    return output;
  }

  function parseDeps(path,text){
    const out=[];
    const base=String(path).split("/").pop().toLowerCase();
    const add=(name,version,ecosystem)=>{
      if(name&&/^\d+\.\d+\.\d+/.test(version))out.push({name,version,ecosystem});
    };
    try{
      if(base==="package-lock.json"){
        for(const [packagePath,pkg] of Object.entries(JSON.parse(text).packages||{})){
          const marker="node_modules/";
          const offset=packagePath.lastIndexOf(marker);
          if(offset>=0&&pkg.version)add(packagePath.slice(offset+marker.length),String(pkg.version),"npm");
        }
      }else if(base.startsWith("requirements")&&base.endsWith(".txt")){
        for(const line of String(text).split(/\r?\n/)){
          const parts=line.split("==");
          if(parts.length===2)add(parts[0].trim(),parts[1].trim().split(";")[0].trim(),"PyPI");
        }
      }
    }catch{}
    return out;
  }

  return {isPlaceholder,tokenIsPlaceholder,redactEvidence,scanText,parseDeps,sourceUrl};
});
