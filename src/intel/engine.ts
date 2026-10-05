import { BaselineTracker, type BaselineSnapshot } from './baseline.ts';
import { CorrelationEngine, type ClusterHit, type GraphSubject } from './graph.ts';

export interface IntelligenceReport {
  readonly clusters: readonly ClusterHit[];
  readonly baselines: readonly BaselineSnapshot[];
}

export class Intelligence {
  readonly graph = new CorrelationEngine();
  readonly baselines = new BaselineTracker();

  observe(subject: GraphSubject, extras: { readonly campaignClicks?: number; readonly hour?: number } = {}): IntelligenceReport {
    const clusters = this.graph.observe(subject);
    const baselines: BaselineSnapshot[] = [];
    if (subject.campaign && extras.campaignClicks !== undefined && extras.hour !== undefined) {
      baselines.push(this.baselines.sample(`campaign:${subject.campaign}:h${extras.hour}`, extras.campaignClicks, subject.now));
    }
    if (subject.campaign && subject.asn !== undefined) {
      baselines.push(this.baselines.sample(`campaign:${subject.campaign}:asn:${subject.asn}`, 1, subject.now, 5));
    }
    return { clusters, baselines };
  }
}
