import { useTranslation } from 'react-i18next';
import type { FlowEvent } from '../types/ui';

interface FlowDetailsProps {
  flow: FlowEvent | null;
  onClose: () => void;
  onTerminateProcess: (pid: number) => void;
  onBlockConnection: (flow: FlowEvent) => void;
}

export function FlowDetails({ flow, onClose, onTerminateProcess, onBlockConnection }: FlowDetailsProps) {
  const { t } = useTranslation();

  if (!flow) {
    return null;
  }

  const handleTerminate = () => {
    if (flow.process && window.confirm(t('flowDetails.confirmTerminate'))) {
      onTerminateProcess(flow.process.pid);
    }
  };

  const handleBlock = () => {
    if (window.confirm(t('flowDetails.confirmBlock'))) {
      onBlockConnection(flow);
    }
  };

  return (
    <div className="flow-details-overlay" onClick={onClose}>
      <div className="flow-details-panel" onClick={(e) => e.stopPropagation()}>
        <div className="panel-header">
          <h2>{t('flowDetails.title')}</h2>
          <button className="close-btn" onClick={onClose} aria-label={t('common.close')}>
            ✕
          </button>
        </div>

        <div className="panel-content">
          {/* Network Information */}
          <section>
            <h3>{t('flowDetails.sections.network')}</h3>
            <div className="details-grid">
              <div className="detail-row">
                <span className="label">{t('flowDetails.protocol')}</span>
                <span className="value">
                  <span className={`proto-indicator proto-${flow.proto.toLowerCase()}`} aria-hidden />
                  {flow.proto}
                </span>
              </div>
              <div className="detail-row">
                <span className="label">{t('flowDetails.source')}</span>
                <span className="value code">{flow.src_ip}:{flow.src_port}</span>
              </div>
              <div className="detail-row">
                <span className="label">{t('flowDetails.destination')}</span>
                <span className="value code">{flow.dst_ip}:{flow.dst_port}</span>
              </div>
              <div className="detail-row">
                <span className="label">{t('flowDetails.interface')}</span>
                <span className="value">{flow.iface ?? 'N/A'}</span>
              </div>
              <div className="detail-row">
                <span className="label">{t('flowDetails.direction')}</span>
                <span className="value">{t(`flows.directions.${flow.direction.toLowerCase()}`)}</span>
              </div>
              <div className="detail-row">
                <span className="label">{t('flowDetails.state')}</span>
                <span className="value">{flow.state ?? 'N/A'}</span>
              </div>
              <div className="detail-row">
                <span className="label">{t('flowDetails.bytes')}</span>
                <span className="value">{flow.bytes.toLocaleString()}</span>
              </div>
              <div className="detail-row">
                <span className="label">{t('flowDetails.packets')}</span>
                <span className="value">{flow.packets.toLocaleString()}</span>
              </div>
            </div>
          </section>

          {/* Process Information */}
          {flow.process && (
            <section>
              <h3>{t('flowDetails.sections.process')}</h3>
              <div className="details-grid">
                <div className="detail-row">
                  <span className="label">{t('flowDetails.processName')}</span>
                  <span className="value">{flow.process.name ?? 'N/A'}</span>
                </div>
                <div className="detail-row">
                  <span className="label">{t('flowDetails.pid')}</span>
                  <span className="value">{flow.process.pid}</span>
                </div>
                <div className="detail-row">
                  <span className="label">{t('flowDetails.ppid')}</span>
                  <span className="value">{flow.process.ppid ?? 'N/A'}</span>
                </div>
                <div className="detail-row">
                  <span className="label">{t('flowDetails.exePath')}</span>
                  <span className="value code">{flow.process.exe_path ?? 'N/A'}</span>
                </div>
                <div className="detail-row">
                  <span className="label">{t('flowDetails.user')}</span>
                  <span className="value">{flow.process.user ?? 'N/A'}</span>
                </div>
                <div className="detail-row">
                  <span className="label">{t('flowDetails.sha256')}</span>
                  <span className="value code">{flow.process.sha256_16 ?? 'N/A'}</span>
                </div>
                <div className="detail-row">
                  <span className="label">{t('flowDetails.signed')}</span>
                  <span className="value">
                    {flow.process.signed !== undefined ? (
                      <span className={`signature ${flow.process.signed ? 'signed' : 'unsigned'}`}>
                        {flow.process.signed ? t('flowDetails.signedYes') : t('flowDetails.signedNo')}
                      </span>
                    ) : (
                      'N/A'
                    )}
                  </span>
                </div>
              </div>
            </section>
          )}

          {/* TLS Information */}
          {(flow.sni || flow.alpn || flow.ja3) && (
            <section>
              <h3>{t('flowDetails.sections.tls')}</h3>
              <div className="details-grid">
                {flow.sni && (
                  <div className="detail-row">
                    <span className="label">{t('flowDetails.sni')}</span>
                    <span className="value code">{flow.sni}</span>
                  </div>
                )}
                {flow.alpn && (
                  <div className="detail-row">
                    <span className="label">{t('flowDetails.alpn')}</span>
                    <span className="value">{flow.alpn}</span>
                  </div>
                )}
                {flow.ja3 && (
                  <div className="detail-row">
                    <span className="label">{t('flowDetails.ja3')}</span>
                    <span className="value code">{flow.ja3}</span>
                  </div>
                )}
              </div>
            </section>
          )}

          {/* DNS Information */}
          {(flow.dns_qname || flow.dns_qtype || flow.dns_rcode) && (
            <section>
              <h3>{t('flowDetails.sections.dns')}</h3>
              <div className="details-grid">
                {flow.dns_qname && (
                  <div className="detail-row">
                    <span className="label">{t('flowDetails.dnsQname')}</span>
                    <span className="value code">{flow.dns_qname}</span>
                  </div>
                )}
                {flow.dns_qtype && (
                  <div className="detail-row">
                    <span className="label">{t('flowDetails.dnsQtype')}</span>
                    <span className="value">{flow.dns_qtype}</span>
                  </div>
                )}
                {flow.dns_rcode && (
                  <div className="detail-row">
                    <span className="label">{t('flowDetails.dnsRcode')}</span>
                    <span className="value">{flow.dns_rcode}</span>
                  </div>
                )}
              </div>
            </section>
          )}

          {/* Layer 2 Information */}
          {flow.layer2 && (
            <section>
              <h3>{t('flowDetails.sections.layer2')}</h3>
              <div className="details-grid">
                <div className="detail-row">
                  <span className="label">{t('flowDetails.l2Kind')}</span>
                  <span className="value">{flow.layer2.kind}</span>
                </div>
                <div className="detail-row">
                  <span className="label">{t('flowDetails.l2Operation')}</span>
                  <span className="value">{flow.layer2.operation}</span>
                </div>
                {flow.layer2.mac_src && (
                  <div className="detail-row">
                    <span className="label">{t('flowDetails.l2MacSrc')}</span>
                    <span className="value code">{flow.layer2.mac_src}</span>
                  </div>
                )}
                {flow.layer2.mac_dst && (
                  <div className="detail-row">
                    <span className="label">{t('flowDetails.l2MacDst')}</span>
                    <span className="value code">{flow.layer2.mac_dst}</span>
                  </div>
                )}
              </div>
            </section>
          )}

          {/* Risk Information */}
          {flow.risk && (
            <section>
              <h3>{t('flowDetails.sections.risk')}</h3>
              <div className="details-grid">
                <div className="detail-row">
                  <span className="label">{t('flowDetails.riskScore')}</span>
                  <span className="value">
                    <span className={`risk-badge risk-${flow.risk.level.toLowerCase()}`}>
                      {flow.risk.score} · {t(`flows.risk.${flow.risk.level.toLowerCase()}`)}
                    </span>
                  </span>
                </div>
                {flow.risk.rule_id && (
                  <div className="detail-row">
                    <span className="label">{t('flowDetails.ruleId')}</span>
                    <span className="value code">{flow.risk.rule_id}</span>
                  </div>
                )}
                {flow.risk.rationale && (
                  <div className="detail-row full-width">
                    <span className="label">{t('flowDetails.rationale')}</span>
                    <span className="value">{flow.risk.rationale}</span>
                  </div>
                )}
              </div>
            </section>
          )}

          {/* Timestamps */}
          <section>
            <h3>{t('flowDetails.sections.timestamps')}</h3>
            <div className="details-grid">
              <div className="detail-row">
                <span className="label">{t('flowDetails.firstSeen')}</span>
                <span className="value">{new Date(flow.ts_first).toLocaleString()}</span>
              </div>
              <div className="detail-row">
                <span className="label">{t('flowDetails.lastSeen')}</span>
                <span className="value">{new Date(flow.ts_last).toLocaleString()}</span>
              </div>
            </div>
          </section>
        </div>

        {/* Actions */}
        <div className="panel-actions">
          <button className="btn btn-danger" onClick={handleBlock}>
            {t('flowDetails.actions.blockConnection')}
          </button>
          {flow.process && (
            <button className="btn btn-danger" onClick={handleTerminate}>
              {t('flowDetails.actions.terminateProcess')}
            </button>
          )}
          <button className="btn btn-secondary" onClick={onClose}>
            {t('common.close')}
          </button>
        </div>
      </div>
    </div>
  );
}
