from django.db import models


class ECUConfig(models.Model):
    base_ecu_id = models.CharField(max_length=100, unique=True)
    last_serial = models.IntegerField(default=0)

    def __str__(self):
        return self.base_ecu_id


class KeyPair(models.Model):
    key_type = models.CharField(max_length=50)
    private_key = models.TextField()
    public_key = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.key_type
