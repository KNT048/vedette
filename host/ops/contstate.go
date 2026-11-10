package ops

import (
	"context"

	"github.com/knt048/vedette/host/api"
)

// readContainers is GET /v1/state/containers (spec 5): per service, whether a unit with a pinned
// digest exists, the digest it pins and the one the running container reports, whether the unit has
// [Install], what systemd says (the output of is-active) and what the container says about its
// health. Versions, previous and the latest pulled image are null until container.pull and
// container.rollback record them (slice 3-7, 3-8). Everything read from podman and systemctl is
// parsed strictly and bounded (D-87): a value that is not one of the known words is "unknown".
func (o *Ops) readContainers(ctx context.Context) (any, error) {
	out := api.ContainersState{Services: make([]api.ContainerState, 0, len(api.Services))}
	for _, svc := range api.Services {
		st := api.ContainerState{Service: svc, UnitState: api.UnitUnknown, Health: api.HealthNone}
		if text, fs := o.readUnit(svc); fs == fileOK {
			if digest, install, err := parseUnit(svc, text); err == nil {
				st.Installed, st.Enabled = true, install
				st.ConfiguredDigest = &digest
			}
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
