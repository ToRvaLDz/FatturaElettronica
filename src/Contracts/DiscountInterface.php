<?php

namespace FatturaElettronicaPhp\FatturaElettronica\Contracts;

use FatturaElettronicaPhp\FatturaElettronica\Enums\DiscountType;

interface DiscountInterface
{
    public function getType(): ?DiscountType;

    public function setType($discountType): DiscountInterface;

    public function getPercentage(): ?float;

    public function setPercentage(?float $discountPercentage): DiscountInterface;

    public function getAmount(): ?float;

    public function setAmount(?float $discountAmount): DiscountInterface;
}
