package ops

import (
	"context"

	"github.com/knt048/vedette/host/api"
)

// readContainers is GET /v1/state/containers (spec 5): per service, whether a unit with a pinned
// digest exists, the digest it pins and the one the running container reports, whether the unit has
// [Install], what systemd says (the output of is-active) and what the container says about its
// health. The version and the previous version come from the versions a start or rollback recorded
// (slice 3-8a), the latest pulled image from container.pull (slice 3-7); each is null until recorded. Everything read from podman and systemctl is
// parsed strictly and bounded (D-87): a value that is not one of the known words is "unknown".
func (o *Ops) readContainers(ctx context.Context) (any, error) {
	out := api.ContainersState{Services: make([]api.ContainerState, 0, len(api.Services))}
	for _, svc := range api.Services {
		st := api.ContainerState{Service: svc, UnitState: api.UnitUnknown, Health: api.HealthNone, LatestPulled: o.latestPulled(svc)}
		if text, fs := o.readUnit(svc); fs == fileOK {
			if digest, install, err := o.ourUnit(svc, text); err == nil {
				st.Installed, st.Enabled = true, install
				st.ConfiguredDigest = &digest
			}
		}
		vs := o.loadVersions(svc)
		if st.ConfiguredDigest != nil && vs.Current != nil && vs.Current.Digest == *st.ConfiguredDigest {
			v := vs.Current.Version
			st.Version = &v
		}
		if vs.Previous != nil {
			v := vs.Previous.Version
			st.Previous = &api.ContainerVersion{Version: &v, Digest: vs.Previous.Digest}
		}
		st.UnitState = o.unitActive(ctx, svc)
		if st.UnitState == api.UnitActive || st.UnitState == api.UnitOther {
			if info, err := o.inspect(ctx, svc); err == nil {
				d := info.Digest
				st.Digest, st.Health = &d, info.Health
			} else {
				st.Health = api.HealthUnknown
			}
		}
		out.Services = append(out.Services, st)
	}
	return out, ctx.Err()
}
