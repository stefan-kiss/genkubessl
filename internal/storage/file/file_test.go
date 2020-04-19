package file

import (
	"os"
	"testing"
)

const TestDirPath = "test/will-be-deleted"

func Test_checkMakeDir(t *testing.T) {
	type args struct {
		directory string
		makeIt    bool
		mode      os.FileMode
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "non existing directory, create it false",
			args: args{
				directory: TestDirPath,
				makeIt:    false,
				mode:      0755,
			},
			wantErr: true,
		},
	}
	err := os.RemoveAll(TestDirPath)
	if err != nil {
		t.Errorf("checkMakeDir() test preparing: cant remove directory: %s: %s", TestDirPath, err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := checkMakeDir(tt.args.directory, tt.args.makeIt, tt.args.mode); (err != nil) != tt.wantErr {
				t.Errorf("checkMakeDir() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
