import { UserRecord, SessionRecord, MemberRecord, ProjectRecord, EnvironmentRecord, ApiCredentialRecord } from '../lib/data-store';
import { Role } from '../lib/permissions';

declare global {
  namespace Express {
    interface Request {
      user?: UserRecord;
      session?: SessionRecord;
      apiKey?: ApiCredentialRecord;
      organizationId?: string;
      projectId?: string;
      environmentId?: string;
      orgRole?: Role;
      membership?: MemberRecord;
      project?: ProjectRecord;
      environment?: EnvironmentRecord;
      requestId?: string;
    }
  }
}
