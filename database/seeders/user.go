package seeders

import (
	"context"
	"zatrano/configs/logconfig"
	"zatrano/models"

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func GetSystemUserConfig() models.User {
	return models.User{
		Name:     "ZATRANO",
		Account:  "zatrano@zatrano",
		Type:     models.Dashboard,
		Password: "ZATRANO",
	}
}

func SeedSystemUser(db *gorm.DB) error {
	systemUserConfig := GetSystemUserConfig()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(systemUserConfig.Password), bcrypt.DefaultCost)
	if err != nil {
		logconfig.Log.Error("Sistem kullanıcısının şifresi hash'lenirken hata oluştu",
			zap.String("account", systemUserConfig.Account),
			zap.Error(err),
		)
		return err
	}

	userToSeed := models.User{
		Name:     systemUserConfig.Name,
		Account:  systemUserConfig.Account,
		Type:     systemUserConfig.Type,
		Password: string(hashedPassword),
		Status:   true,
	}

	var existingUser models.User
	result := db.Where("account = ? AND type = ?", userToSeed.Account, userToSeed.Type).First(&existingUser)

	if result.Error == nil {
		logconfig.SLog.Info("Sistem kullanıcısı '%s' zaten mevcut. Güncelleme gerekip gerekmediği kontrol ediliyor...", userToSeed.Account)

		updateFields := make(map[string]interface{})
		needsUpdate := false

		if existingUser.Name != userToSeed.Name {
			updateFields["name"] = userToSeed.Name
			needsUpdate = true
		}
		if !existingUser.Status {
			updateFields["status"] = true
			needsUpdate = true
		}

		if needsUpdate {
			logconfig.SLog.Info("Mevcut sistem kullanıcısı '%s' güncelleniyor...", userToSeed.Account)

			ctx := context.WithValue(context.Background(), "user_id", uint(1))
			err := db.WithContext(ctx).Model(&existingUser).Updates(updateFields).Error
			if err != nil {
				logconfig.Log.Error("Mevcut sistem kullanıcısı güncellenemedi",
					zap.String("account", userToSeed.Account),
					zap.Error(err),
				)
				return err
			}
			logconfig.SLog.Info("Mevcut sistem kullanıcısı '%s' başarıyla güncellendi.", userToSeed.Account)
		} else {
			logconfig.SLog.Info("Mevcut sistem kullanıcısı '%s' için güncelleme gerekmiyor.", userToSeed.Account)
		}
		return nil

	} else if result.Error != gorm.ErrRecordNotFound {
		logconfig.Log.Error("Sistem kullanıcısı kontrol edilirken veritabanı hatası",
			zap.String("account", userToSeed.Account),
			zap.Error(result.Error),
		)
		return result.Error
	}

	logconfig.SLog.Info("Sistem kullanıcısı '%s' bulunamadı. Oluşturuluyor...", userToSeed.Account)

	ctx := context.WithValue(context.Background(), "user_id", uint(1))
	err = db.WithContext(ctx).Create(&userToSeed).Error
	if err != nil {
		logconfig.Log.Error("Sistem kullanıcısı oluşturulamadı",
			zap.String("account", userToSeed.Account),
			zap.Error(err),
		)
		return err
	}

	logconfig.SLog.Info("Sistem kullanıcısı '%s' başarıyla oluşturuldu.", userToSeed.Account)
	return nil
}
