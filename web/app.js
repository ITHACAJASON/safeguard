'use strict';
const byId = id => document.getElementById(id);
const roles = ['analyst','supervisor','auditor'];
const statusLabels = {allowed:'已放行',pending:'待审批',approved:'已批准',rejected:'已拒绝',denied:'已拦截',executed:'已执行',consumed:'已使用',expired:'已过期',error:'请求未完成',proposed:'建议已生成',ok:'已完成'};
const actionLabels = {read_request:'读取采购单',export_request:'导出采购单',send_order:'发送采购订单',approve:'批准',reject:'拒绝'};
const reasonLabels = {
  REQUEST_NOT_ASSIGNED:'该采购单未分配给当前分析员。',
  ROLE_NOT_ALLOWED:'当前角色不具备操作权限。',
  ORDER_AUTOMATION_FORBIDDEN:'演示规则禁止 Agent 直接发单。',
  UNKNOWN_ACTION:'当前动作不在网关允许列表内。',
  RECIPIENT_NOT_ALLOWED:'接收方不在演示规则允许范围内。',
  APPROVAL_NOT_FOUND:'找不到对应审批。',
  APPROVAL_EXPIRED:'本次批准已过期。',
  APPROVAL_NOT_PENDING:'该审批当前不能更新。',
  APPROVAL_BINDING_MISMATCH:'批准不适用于这次操作。',
  APPROVAL_VERSION_CHANGED:'文件或规则已变更，请重新申请。',
  APPROVAL_USED:'本次批准已使用。',
  APPROVAL_NOT_CURRENT:'本次批准已不可用，请重新申请。',
  APPROVAL_REQUIRED:'请先经主管批准。',
  APPROVAL_PENDING:'尚未取得主管批准。',
  APPROVAL_NOT_APPROVED:'尚未取得主管批准。',
  APPROVAL_ALREADY_USED:'本次批准已使用，不会再次执行。',
  APPROVAL_REJECTED:'主管已拒绝本次导出。',
  APPROVAL_APPROVED:'主管批准了本次导出。请回到分析员执行。',
  SUPERVISOR_APPROVAL_REQUIRED:'该操作需要主管批准。',
  ASSIGNED_REQUEST:'已核对采购单分配权限。',
  REQUEST_READ_ALLOWED:'已核对采购单分配权限。',
  request_not_assigned:'该采购单未分配给当前分析员。',
  not_assigned:'该采购单未分配给当前分析员。',
  forbidden:'当前角色不具备操作权限。',
  order_not_permitted:'演示策略禁止 Agent 直接发单。',
  action_not_allowed:'当前规则不允许该操作。',
  invalid_recipient:'接收方与规则不符。',
  approval_required:'必须先经主管批准。',
  approval_mismatch:'批准与这次申请不匹配。',
  approval_used:'本次批准已使用。',
  approval_expired:'本次批准已过期。'
};
const state = {role:'analyst',lastApproval:null};
const examples = {read:['read_request','PR-1001'],out:['read_request','PR-2002'],export:['export_request','PR-1001'],order:['send_order','PR-1001']};
function node(tag,text,className) {
  const item = document.createElement(tag);
  if (text !== undefined) item.textContent = String(text);
  if (className) item.className = className;
  return item;
}
function shown(value) { return value === undefined || value === null || value === '' ? '—' : String(value); }
function displayTime(value) {
  if (typeof value !== 'number') return shown(value);
  const date=new Date(value*(value < 1e12 ? 1000 : 1));
  return Number.isFinite(date.getTime()) ? date.toISOString().replace('T',' ').replace(/\.\d+Z$/,' UTC') : shown(value);
}
function label(value, map) { return Object.hasOwn(map,value) ? map[value] : shown(value); }
function badge(status) {
  const known = Object.hasOwn(statusLabels,status);
  return node('span',known ? statusLabels[status] : shown(status), 'pill ' + (known ? status : 'neutral'));
}
async function api(path, method='GET', payload, role=state.role) {
  const opts = {method,headers:{Accept:'application/json'},credentials:'same-origin',cache:'no-store'};
  if (role) opts.headers.Authorization = 'Bearer demo-' + role;
  if (payload !== undefined) {
    opts.headers['Content-Type']='application/json';
    opts.body=JSON.stringify(payload);
  }
  try {
    const response = await fetch(path,opts);
    let body;
    try { body = await response.json(); } catch { body = null; }
    if (!body || typeof body !== 'object' || Array.isArray(body)) return {status:'error',reason:`接口返回异常（HTTP ${response.status}）`};
    if (!response.ok && !body.status) return {...body,status:'error',reason:body.reason || body.error || `HTTP ${response.status}`};
    return body;
  } catch {
    return {status:'error',reason:'无法连接本地网关，请检查服务是否运行。'};
  }
}
function renderReceipt(result, fallback, displayStatus) {
  const status=displayStatus || result.status || 'ok';
  const body=byId('receipt'), raw=byId('raw');
  const reason=label(result.reason || result.error,reasonLabels);
  body.replaceChildren(badge(status),node('p',fallback || (reason !== '—' ? reason : '已收到网关回执。')));
  if (result.approval_id) body.append(node('p','审批编号：'+result.approval_id));
  if (status === 'allowed' && result.data) {
    const info=result.data;
    const title=info.title || info.name || info.subject;
    if (title) body.append(node('p',title));
  }
  byId('raw-wrap').hidden=false;
  raw.textContent=JSON.stringify(result,null,2);
}
function refreshFields() {
  const isExport=byId('action').value==='export_request';
  const approval=byId('approval-id').value.trim();
  byId('export-fields').hidden=!isExport;
  byId('recipient').required=isExport;
  byId('submit-action').textContent=isExport?(approval?'执行已获批的导出':'发起导出审批'):'交给网关判定';
  const hint=state.lastApproval && isExport && approval===state.lastApproval ? '如已批准，可提交执行。' : '';
  byId('approval-tip').textContent=hint;
}
function chooseExample(key) {
  const sample=examples[key];
  byId('action').value=sample[0];
  byId('request-id').value=sample[1];
  byId('approval-id').value='';
  byId('recipient').value='ops@example.test';
  refreshFields();
}
async function withButton(button, fn) {
  if (button.disabled) return;
  button.disabled=true;
  try { await fn(); } finally { button.disabled=false; }
}
async function loadAssigned() {
  const result=await api('/api/requests','GET',undefined,'analyst');
  if (!Array.isArray(result.items)) return;
  const list=result.items.map(record=>{
    const option=document.createElement('option');
    option.value=typeof record==='string' ? record : record.request_id || record.id || '';
    if (record && record.title) option.label=record.title;
    return option;
  }).filter(option=>option.value);
  byId('assigned').replaceChildren(...list);
}
async function loadApprovals() {
  const target=byId('approval-list');
  const result=await api('/api/approvals','GET',undefined,'supervisor');
  if (!Array.isArray(result.items)) {
    target.textContent=label(result.reason || '审批列表未能读取。',reasonLabels); return;
  }
  const items=result.items;
  if (!items.length) { target.textContent='暂无审批。先用采购分析员角色发起一次导出。'; return; }
  const cards=items.map(item=>{
    const id=item.approval_id || item.id;
    const status=item.status || item.state;
    const card=node('article',undefined,'row');
    card.append(node('strong',shown(item.request_id || item.resource_id)),badge(status),
      node('p','接收方：'+shown(item.recipient)),
      node('p','审批编号：'+shown(id)));
    if (item.expires_at) card.append(node('p','有效期至：'+displayTime(item.expires_at)));
    if (status==='pending' && id) {
      const controls=node('div',undefined,'row-actions');
      for(const decision of ['approve','reject']){
        const btn=node('button',label(decision,actionLabels),decision==='approve'?'primary':'secondary');
        btn.type='button';
        btn.addEventListener('click',()=>{
          if ([...controls.children].some(el=>el.disabled)) return;
          [...controls.children].forEach(el=>{el.disabled=true;});
          void (async()=>{
            try {
              const response=await api('/api/approvals/'+encodeURIComponent(id),'POST',{decision},'supervisor');
              renderReceipt(response);
              const responseStatus=response.status || response.state;
              if (responseStatus==='approved' || (decision==='approve' && ['ok','allowed'].includes(responseStatus))) {
                state.lastApproval=id;
                byId('action').value='export_request';
                byId('request-id').value=item.request_id || item.resource_id || '';
                byId('recipient').value=item.recipient || 'ops@example.test';
                byId('approval-id').value=id;
                refreshFields();
              }
              await loadApprovals();
            } finally { [...controls.children].forEach(el=>{el.disabled=false;}); }
          })();
        });
        controls.append(btn);
      }
      card.append(controls);
    }
    return card;
  });
  target.replaceChildren(...cards);
}
async function loadAudit() {
  const target=byId('audit-list');
  const result=await api('/api/audit','GET',undefined,'auditor');
  if (!Array.isArray(result.items)) {target.textContent=label(result.reason || '审计记录未能读取。',reasonLabels); return;}
  if (!result.items.length) {target.textContent='暂无记录。先由分析员提交一项操作。';return;}
  const cards=result.items.map(item=>{
    const card=node('article',undefined,'row');
    const title=label(item.action || item.event || item.event_type || '事件',actionLabels);
    const status=item.status || item.decision || item.outcome;
    card.append(node('strong',title),badge(status));
    card.append(node('p','时间：'+displayTime(item.timestamp || item.created_at || item.at || item.ts || item.time)),
      node('p','对象：'+shown(item.request_id || item.resource_id)+'　角色：'+shown(item.role || item.actor)));
    const reason=item.reason || item.reason_code;
    const rule=item.rule_version || item.policy_version;
    if (rule || reason) card.append(node('p','规则：'+shown(rule)+'　原因：'+label(reason,reasonLabels)));
    if (item.approval_id || item.approver) card.append(node('p','审批编号：'+shown(item.approval_id)+'　审批人：'+shown(item.approver)));
    const view=node('details'),summary=node('summary','查看此条记录');
    view.append(summary,node('pre',JSON.stringify(item,null,2)));
    card.append(view);
    return card;
  });
  target.replaceChildren(...cards);
}
const loaders={analyst:loadAssigned,supervisor:loadApprovals,auditor:loadAudit};
function switchRole(role) {
  if(!roles.includes(role))return;
  state.role=role;
  for (const name of roles) {
    byId(name).hidden=name!==role;
    document.querySelector('[data-role='+name+']').setAttribute('aria-pressed',String(role===name));
  }
  void loaders[role]();
}
async function loadHealth() {
  const response=await api('/api/health','GET',undefined,null);
  const healthy=response.status!=='error' && response.status!=='denied';
  const connection=byId('connection');
  connection.textContent=healthy?'网关已连接':'网关未连接';
  connection.className='connection '+(healthy?'good':'bad');
}
document.querySelectorAll('[data-example]').forEach(el=>el.addEventListener('click',()=>chooseExample(el.dataset.example)));
document.querySelectorAll('[data-role]').forEach(el=>el.addEventListener('click',()=>switchRole(el.dataset.role)));
document.querySelectorAll('[data-refresh]').forEach(el=>el.addEventListener('click',()=>void withButton(el,loaders[el.dataset.refresh])));
byId('action').addEventListener('change',refreshFields);
byId('approval-id').addEventListener('input',refreshFields);
byId('action-form').addEventListener('submit',event=>{
  event.preventDefault();
  const action=byId('action').value;
  const payload={action,request_id:byId('request-id').value.trim()};
  if(action==='export_request'){
    payload.recipient=byId('recipient').value.trim();
    const approval=byId('approval-id').value.trim();
    if(approval)payload.approval_id=approval;
  }
  void withButton(byId('submit-action'),async()=>{
    const result=await api('/api/action','POST',payload,'analyst');
    const messages={pending:'已生成审批。请切到「采购主管」批准，再回到分析员执行。',allowed:action==='export_request'?'已完成本地脱敏导出。未发送到外部收件地址。':'操作已通过网关并执行。'};
    renderReceipt(result,Object.hasOwn(messages,result.status)?messages[result.status]:undefined);
    if (result.status==='pending' && result.approval_id) {
      state.lastApproval=null;
      byId('approval-tip').textContent='导出审批已发起。';
    }
  });
});
byId('proposal-form').addEventListener('submit',event=>{
  event.preventDefault();
  void withButton(event.submitter || byId('proposal-form').querySelector('button'),async()=>{
    const response=await api('/api/propose','POST',{message:byId('message').value.trim()},'analyst');
    const p=response.proposal || response.data || response;
    if (p && Object.hasOwn(actionLabels,p.action) && ['read_request','export_request','send_order'].includes(p.action) && typeof p.request_id==='string') {
      byId('action').value=p.action;
      byId('request-id').value=p.request_id;
      byId('approval-id').value='';
      byId('recipient').value=p.recipient || 'ops@example.test';
      refreshFields();
      renderReceipt(response,'已填入建议，尚未执行。请核对后手动提交。','proposed');
    } else renderReceipt(response);
  });
});
refreshFields();
void loadHealth();
void loadAssigned();
